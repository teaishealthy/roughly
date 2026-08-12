from __future__ import annotations

import contextlib
import struct
from dataclasses import dataclass
from itertools import pairwise
from typing import TYPE_CHECKING, Literal

from roughly import tags
from roughly.errors import FormatError, PacketError
from roughly.shared import (
    GOOGLE_ROUGHTIME_SENTINEL,
    PACKET_SIZE,
    ROUGHTIM,
    UINT32_SIZE,
    VERSIONS_SUPPORTED,
    ProtocolProfile,
    convert_mjd_to_unix,
    find_by_tag,
    get_by_tag,
    microseconds_to_seconds,
    split_into_chunks,
    unpack_uint32,
    unpack_uint32_list,
    unpack_uint64,
)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ed25519


__all__ = (
    "Certificate",
    "Delegation",
    "Message",
    "Packet",
    "Response",
    "SignedResponse",
    "Tag",
)


@dataclass
class Tag:
    tag: int  # uint32
    value: bytes


def _validate_offsets(raw_offsets: tuple[int, ...], values_len: int) -> list[int]:
    offsets = [0, *raw_offsets]
    for previous, offset in pairwise(offsets):
        if offset % UINT32_SIZE != 0:
            raise PacketError(f"Tag value offset {offset} is not a multiple of {UINT32_SIZE}")
        if offset < previous:
            raise PacketError("Tag value offsets must be non-decreasing")
        if offset > values_len:
            raise PacketError(
                f"Tag value offset {offset} lies past the {values_len}-byte tag value section"
            )
    return offsets


@dataclass
class Message:
    tags: list[Tag]

    def size(self) -> int:
        # 4 bytes for the number of pairs,
        # 4 bytes for each offset (N-1 offsets),
        # and 4 bytes for each tag (N tags)
        header_size = 4 + (len(self.tags) - 1) * 4 + len(self.tags) * 4
        value_size = sum(len(tag.value) for tag in self.tags)
        return header_size + value_size

    def debug_print(self) -> None:
        for tag in self.tags:
            tag_ascii = tag.tag.to_bytes(4, "little").decode("ascii", errors="replace")
            print(f"Tag {tag_ascii}: {tag.value}")  # noqa: T201

    def to_bytes(self) -> bytes:
        num_pairs = len(self.tags)
        if num_pairs == 0:
            raise FormatError("Message must contain at least one tag")

        value_blobs: list[bytes] = []
        for tag in self.tags:
            val_data = tag.value

            if len(val_data) % 4 != 0:
                raise FormatError(
                    f"Value for tag {tag.tag:#x} is not 4-byte aligned (len={len(val_data)})"
                )

            value_blobs.append(val_data)

        # Compute offsets: first offset is implicit 0; encode offsets for entries 1..N-1
        offsets: list[int] = []
        running = 0
        for blob in value_blobs[:-1]:
            running += len(blob)
            offsets.append(running)

        header = struct.pack("<I", num_pairs)
        for offset in offsets:
            header += struct.pack("<I", offset)
        for tag in self.tags:
            header += struct.pack("<I", tag.tag)

        values_data = b"".join(value_blobs)
        return header + values_data

    def prepare(self) -> None:
        """Prepares a Roughtime message for sending."""
        self.tags.sort(key=lambda t: t.tag)
        self.zzzz()

    def zzzz(self) -> None:
        # fill the message with a ZZZZ tag to pad until 1024 bytes
        current_size = len(self.to_bytes())
        if current_size >= PACKET_SIZE:
            return  # already at or above 1024 bytes

        zzzz_tag = Tag(tag=tags.ZZZZ, value=b"")
        self.tags.append(zzzz_tag)

        current_size = Packet.header_size + self.size()

        zlen = PACKET_SIZE - current_size
        zzzz_tag.value = b"\x00" * zlen

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        if len(data) < UINT32_SIZE:
            raise PacketError(f"Message is too short to hold a tag count (len={len(data)})")

        (num_pairs,) = struct.unpack_from("<I", data, 0)
        if num_pairs == 0:
            raise PacketError("Message contains zero tag-value pairs")

        offsets_count = num_pairs - 1
        offsets_end = UINT32_SIZE + offsets_count * UINT32_SIZE
        tags_end = offsets_end + num_pairs * UINT32_SIZE

        if tags_end > len(data):
            raise PacketError(
                f"Message declares {num_pairs} tag-value pairs but is only {len(data)} bytes long"
            )

        raw_offsets: tuple[int, ...] = (
            struct.unpack_from(f"<{offsets_count}I", data, UINT32_SIZE) if offsets_count else ()
        )
        raw_tags: tuple[int, ...] = struct.unpack_from(f"<{num_pairs}I", data, offsets_end)

        values_data = data[tags_end:]
        if len(values_data) % UINT32_SIZE != 0:
            raise PacketError(
                f"Tag values are not {UINT32_SIZE}-byte aligned (len={len(values_data)})"
            )

        offsets = _validate_offsets(raw_offsets, len(values_data))

        for i in range(1, num_pairs):
            if raw_tags[i] <= raw_tags[i - 1]:
                raise PacketError(
                    f"Tags must be strictly ascending; "
                    f"{raw_tags[i]:#x} follows {raw_tags[i - 1]:#x}"
                )

        tag_list: list[Tag] = []
        for i in range(num_pairs):
            start = offsets[i]
            end = offsets[i + 1] if i + 1 < num_pairs else len(values_data)
            tag_list.append(Tag(tag=raw_tags[i], value=values_data[start:end]))

        return cls(tags=tag_list)


_DEFAULT_PROFILE = ProtocolProfile.from_version(max(VERSIONS_SUPPORTED))


@dataclass
class Packet:
    message: Message
    magic: int = ROUGHTIM

    header_size: Literal[12] = 12

    framed: bool = True

    def dump(self, *, profile: ProtocolProfile = _DEFAULT_PROFILE) -> bytes:
        message_data = self.message.to_bytes()
        data = b""

        if profile.packet_framing:
            data += struct.pack("<Q", self.magic)
            data += struct.pack("<I", len(message_data))

        data += message_data
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> Packet:
        if len(data) < cls.header_size:
            raise PacketError(f"Packet is too short to be a Roughtime packet (len={len(data)})")

        magic, msg_len = struct.unpack("<QI", data[: cls.header_size])
        if magic != cls.magic:
            # we might be interacting with Google Roughtime
            with contextlib.suppress(PacketError):
                return cls(message=Message.from_bytes(data), framed=False)

            raise PacketError(f"Expected magic {cls.magic:#x}, got {magic:#x}")

        if len(data) != 12 + msg_len:
            raise PacketError(
                f"Packet length {len(data)} does not match declared message length {msg_len}"
            )

        msg_data = data[12 : 12 + msg_len]
        message = Message.from_bytes(msg_data)
        return cls(message=message)


@dataclass
class SignedResponse:
    radius: int
    midpoint: int
    version: int
    versions: tuple[int, ...]
    root: bytes

    @classmethod
    def from_bytes(cls, data: bytes, *, profile: ProtocolProfile) -> SignedResponse:
        message = Message.from_bytes(data)
        radius_tag = get_by_tag(message.tags, tags.RADI)
        midpoint_tag = get_by_tag(message.tags, tags.MIDP)
        versions_tag = find_by_tag(message.tags, tags.VERS)
        version_tag = find_by_tag(message.tags, tags.VER)
        root_tag = get_by_tag(message.tags, tags.ROOT)
        radius = unpack_uint32(radius_tag.value, what="RADI")
        midpoint = unpack_uint64(midpoint_tag.value, what="MIDP")

        if profile.use_mjd:
            midpoint = convert_mjd_to_unix(midpoint)
            radius = max(1, microseconds_to_seconds(radius))

        versions = unpack_uint32_list(versions_tag.value, what="VERS") if versions_tag else ()
        version = unpack_uint32(version_tag.value, what="VER") if version_tag else 0
        root = root_tag.value

        return cls(
            radius=radius,
            midpoint=midpoint,
            versions=versions,
            version=version,
            root=root,
        )

    def to_bytes(self) -> bytes:
        message = Message(
            tags=[
                Tag(tag=tags.RADI, value=struct.pack("<I", self.radius)),
                Tag(tag=tags.MIDP, value=struct.pack("<Q", self.midpoint)),
                Tag(tag=tags.ROOT, value=self.root),
            ]
        )
        # GOOGLE_ROUGHTIME_SENTINEL is 128-bit and cannot be packed as u32;
        # vroughtime clients also expect no VER/VERS tags in the signed response.
        if self.version != GOOGLE_ROUGHTIME_SENTINEL:
            message.tags.append(Tag(tag=tags.VER, value=struct.pack("<I", self.version)))
            message.tags.append(
                Tag(tag=tags.VERS, value=b"".join(struct.pack("<I", v) for v in self.versions))
            )

        message.tags.sort(key=lambda t: t.tag)
        return message.to_bytes()


@dataclass
class Delegation:
    public_key: bytes
    min_time: int
    max_time: int

    @classmethod
    def from_bytes(cls, data: bytes, *, profile: ProtocolProfile) -> Delegation:
        dele_message = Message.from_bytes(data)

        pubk_tag = get_by_tag(dele_message.tags, tags.PUBK)
        mint_tag = get_by_tag(dele_message.tags, tags.MINT)
        maxt_tag = get_by_tag(dele_message.tags, tags.MAXT)

        public_key = pubk_tag.value
        min_time = unpack_uint64(mint_tag.value, what="MINT")
        max_time = unpack_uint64(maxt_tag.value, what="MAXT")

        if profile.use_mjd:
            min_time = convert_mjd_to_unix(min_time)
            max_time = convert_mjd_to_unix(max_time)

        return cls(
            public_key=public_key,
            min_time=min_time,
            max_time=max_time,
        )

    def to_bytes(self) -> bytes:
        message = Message(
            tags=[
                Tag(tag=tags.PUBK, value=self.public_key),
                Tag(tag=tags.MINT, value=struct.pack("<Q", self.min_time)),
                Tag(tag=tags.MAXT, value=struct.pack("<Q", self.max_time)),
            ]
        )
        message.tags.sort(key=lambda t: t.tag)
        return message.to_bytes()


@dataclass
class Certificate:
    delegation: Delegation
    signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes, *, profile: ProtocolProfile) -> Certificate:
        message = Message.from_bytes(data)
        dele_tag = get_by_tag(message.tags, tags.DELE)
        delegation = Delegation.from_bytes(dele_tag.value, profile=profile)

        signature_tag = get_by_tag(message.tags, tags.SIG)
        signature = signature_tag.value

        return cls(delegation=delegation, signature=signature)

    @classmethod
    def signed(
        cls,
        delegation: Delegation,
        *,
        private_key: ed25519.Ed25519PrivateKey,
        context_string: bytes,
    ) -> Certificate:
        dele_bytes = delegation.to_bytes()
        signature = private_key.sign(context_string + dele_bytes)
        return cls(delegation=delegation, signature=signature)

    def to_bytes(self) -> bytes:
        message = Message(
            tags=[
                Tag(tag=tags.DELE, value=self.delegation.to_bytes()),
                Tag(tag=tags.SIG, value=self.signature),
            ]
        )
        message.tags.sort(key=lambda t: t.tag)
        return message.to_bytes()


@dataclass
class Response:
    """Shared response data model for both client and server."""

    signature: bytes
    """The signature over the signed response"""

    nonce: bytes
    """The nonce used in the request/response"""

    type: int | None
    """The type of the response (should be TYPE_RESPONSE). May be None for < draft-14."""

    path: list[bytes]
    """The PATH tag value from the response. Used for the Merkle tree."""

    signed_response: SignedResponse
    """The parsed signed response"""

    certificate: Certificate
    """The certificate used to derive the public key."""

    index: int
    """The index of the server in the Merkle tree."""

    def to_message(self, *, profile: ProtocolProfile) -> Message:
        """Serialize to a Roughtime message for sending."""
        srep_raw = self.signed_response.to_bytes()

        resp = Message(
            tags=[
                Tag(tag=tags.SIG, value=self.signature),
                Tag(tag=tags.NONC, value=self.nonce),
                Tag(tag=tags.PATH, value=b"".join(self.path)),
                Tag(tag=tags.SREP, value=srep_raw),
                Tag(tag=tags.CERT, value=self.certificate.to_bytes()),
                Tag(tag=tags.INDX, value=struct.pack("<I", self.index)),
            ]
        )

        if profile.packet_framing:
            resp.tags.append(Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_RESPONSE)))

        if profile.ver_tag_in_response:
            resp.tags.append(Tag(tag=tags.VER, value=struct.pack("<I", profile.version)))

        resp.tags.sort(key=lambda t: t.tag)
        return resp

    @classmethod
    def from_message(
        cls,
        message: Message,
        *,
        profile: ProtocolProfile,
    ) -> tuple[Response, bytes, bytes]:
        """Parse from a Roughtime message.

        Returns the Response and the raw bytes of DELE and SREP tags
        (needed for signature verification).
        """
        sig = get_by_tag(message.tags, tags.SIG)
        nonc = get_by_tag(message.tags, tags.NONC)

        type_tag = find_by_tag(message.tags, tags.TYPE)
        type = None
        if type_tag is not None:
            type = unpack_uint32(type_tag.value, what="TYPE")

            if type != tags.TYPE_RESPONSE:
                raise PacketError(f"Expected TYPE_RESPONSE, got {type}")

        path = get_by_tag(message.tags, tags.PATH)
        srep = get_by_tag(message.tags, tags.SREP)
        cert = get_by_tag(message.tags, tags.CERT)
        indx = get_by_tag(message.tags, tags.INDX)

        # Extract raw DELE bytes from CERT for signature verification
        cert_msg = Message.from_bytes(cert.value)
        # get_by_tag, not always(): a CERT without DELE is malformed input,
        # not a broken invariant.
        dele = get_by_tag(cert_msg.tags, tags.DELE)

        response = cls(
            signature=sig.value,
            nonce=nonc.value,
            type=type,
            path=split_into_chunks(path.value, 32),
            signed_response=SignedResponse.from_bytes(srep.value, profile=profile),
            certificate=Certificate.from_bytes(cert.value, profile=profile),
            index=unpack_uint32(indx.value, what="INDX"),
        )

        return response, dele.value, srep.value
