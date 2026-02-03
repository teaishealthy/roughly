from __future__ import annotations

import contextlib
import io
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from roughly import tags
from roughly.errors import FormatError, PacketError
from roughly.shared import (
    DRAFT_VERSION_ZERO,
    GOOGLE_ROUGHTIME_SENTINEL,
    PACKET_SIZE,
    ROUGHTIM,
    always,
    convert_mjd_to_unix,
    find_by_predicate,
    microseconds_to_seconds,
    pop_by_tag,
    pop_by_tag_optional,
    split_into_chunks,
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


@dataclass
class Message:
    tags: list[Tag]

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

        current_size = len(Packet(message=self).dump())

        zlen = PACKET_SIZE - current_size
        zzzz_tag.value = b"\x00" * zlen

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        reader = io.BytesIO(data)
        (num_pairs,) = struct.unpack("<I", reader.read(4))
        if num_pairs == 0:
            raise PacketError("Message contains zero tag-value pairs")

        offsets = [0]

        for _ in range(num_pairs - 1):
            (offset,) = struct.unpack("<I", reader.read(4))
            offsets.append(offset)

        tags: list[int] = []
        for _ in range(num_pairs):
            (tag,) = struct.unpack("<I", reader.read(4))
            tags.append(tag)

        values_start = reader.tell()
        values_data = data[values_start:]

        tag_list: list[Tag] = []
        for i in range(num_pairs):
            start = offsets[i]
            end = offsets[i + 1] if i + 1 < num_pairs else len(values_data)
            val_data = values_data[start:end]

            tag_list.append(Tag(tag=tags[i], value=val_data))

        return cls(tags=tag_list)


@dataclass
class Packet:
    message: Message
    magic: int = ROUGHTIM

    def dump(self, *, google: bool = False) -> bytes:
        message_data = self.message.to_bytes()
        data = b""

        # VDIFF: Google Roughtime clients omit the magic and length fields
        if not google:
            data += struct.pack("<Q", self.magic)
            data += struct.pack("<I", len(message_data))

        data += message_data
        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> Packet:
        magic, msg_len = struct.unpack("<QI", data[:12])
        if magic != cls.magic:
            # we might be interacting with Google Roughtime
            with contextlib.suppress(PacketError):
                return cls(message=Message.from_bytes(data))

            raise PacketError(f"Expected magic {cls.magic:#x}, got {magic:#x}")

        if len(data) < 12 + msg_len:
            raise PacketError("Packet data is shorter than declared message length")

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
    def from_bytes(cls, data: bytes, *, draft7: bool = False) -> SignedResponse:
        message = Message.from_bytes(data)
        radius_tag = pop_by_tag(message.tags, tags.RADI)
        midpoint_tag = pop_by_tag(message.tags, tags.MIDP)
        versions_tag = pop_by_tag_optional(message.tags, tags.VERS)
        version_tag = pop_by_tag_optional(message.tags, tags.VER)
        root_tag = pop_by_tag(message.tags, tags.ROOT)
        (radius,) = struct.unpack("<I", radius_tag.value)
        (midpoint,) = struct.unpack("<Q", midpoint_tag.value)

        # VDIFF: draft-7 uses MJD for midpoint and radius in microseconds
        if draft7:
            midpoint = convert_mjd_to_unix(midpoint)
            # We lose a ton of precision here, but I don't really care about draft-7 that much
            # later specs require a radius of at least 1 second anyway
            radius = max(1, microseconds_to_seconds(radius))

        versions = (
            struct.unpack(f"<{len(versions_tag.value) // 4}I", versions_tag.value)
            if versions_tag
            else ()
        )
        version = struct.unpack("<I", version_tag.value)[0] if version_tag else 0
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
        # VDIFF: we can't pack GOOGLE_ROUGHTIME_SENTINEL as a u32
        # vroughtime clients expect no VER/VERS tags at all
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
    def from_bytes(cls, data: bytes, *, draft7: bool = False) -> Delegation:
        dele_message = Message.from_bytes(data)

        pubk_tag = pop_by_tag(dele_message.tags, tags.PUBK)
        mint_tag = pop_by_tag(dele_message.tags, tags.MINT)
        maxt_tag = pop_by_tag(dele_message.tags, tags.MAXT)

        public_key = pubk_tag.value
        (min_time,) = struct.unpack("<Q", mint_tag.value)
        (max_time,) = struct.unpack("<Q", maxt_tag.value)

        # VDIFF: draft-7 uses MJD for min_time and max_time
        if draft7:
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
    def from_bytes(cls, data: bytes, *, draft7: bool = False) -> Certificate:
        message = Message.from_bytes(data)
        dele_tag = pop_by_tag(message.tags, tags.DELE)
        delegation = Delegation.from_bytes(dele_tag.value, draft7=draft7)

        signature_tag = pop_by_tag(message.tags, tags.SIG)
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

    def to_message(self, *, version: int) -> Message:
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

        # VDIFF: vroughtime issue
        if version != GOOGLE_ROUGHTIME_SENTINEL:
            resp.tags.append(Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_RESPONSE)))

        if version <= DRAFT_VERSION_ZERO | 11:
            resp.tags.append(Tag(tag=tags.VER, value=struct.pack("<I", version)))

        resp.tags.sort(key=lambda t: t.tag)
        return resp

    @classmethod
    def from_message(
        cls,
        message: Message,
        *,
        draft7: bool = False,
    ) -> tuple[Response, bytes, bytes]:
        """Parse from a Roughtime message.

        Returns the Response and the raw bytes of DELE and SREP tags
        (needed for signature verification).
        """
        tag_list = message.tags.copy()
        sig = pop_by_tag(tag_list, tags.SIG)
        nonc = pop_by_tag(tag_list, tags.NONC)

        type = pop_by_tag_optional(tag_list, tags.TYPE)
        if type is not None:
            (type,) = struct.unpack("<I", type.value)

            if type != tags.TYPE_RESPONSE:
                raise PacketError(f"Expected TYPE_RESPONSE, got {type}")

        path = pop_by_tag(tag_list, tags.PATH)
        srep = pop_by_tag(tag_list, tags.SREP)
        cert = pop_by_tag(tag_list, tags.CERT)
        indx = pop_by_tag(tag_list, tags.INDX)

        # Extract raw DELE bytes from CERT for signature verification
        cert_msg = Message.from_bytes(cert.value)
        dele_idx = always(find_by_predicate(cert_msg.tags, lambda t: t.tag == tags.DELE))
        dele_raw = cert_msg.tags[dele_idx].value

        response = cls(
            signature=sig.value,
            nonce=nonc.value,
            type=type,
            path=split_into_chunks(path.value, 4),
            signed_response=SignedResponse.from_bytes(srep.value, draft7=draft7),
            certificate=Certificate.from_bytes(cert.value, draft7=draft7),
            index=struct.unpack("<I", indx.value)[0],
        )

        return response, dele_raw, srep.value
