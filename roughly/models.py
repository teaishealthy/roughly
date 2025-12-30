from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import tags

ROUGHTIM = 0x4D49544847554F52
RESPONSE_CONTEXT_STRING = b"RoughTime v1 response signature\x00"
DELEGATION_CONTEXT_STRING = b"RoughTime v1 delegation signature\x00"

VERSIONS_SUPPORTED = (1, 0x8000000C)


def build_request(
    versions: tuple[int, ...] = VERSIONS_SUPPORTED, public_key: bytes | None = None
) -> Packet:
    """Build a spec-compliant request padded to 1024 bytes (UDP)."""

    ver = b"".join(struct.pack("<I", v) for v in versions)  # VER: uint32 list
    nonce = os.urandom(32)  # NONC: 32 random bytes

    tag_list: list[Tag] = [
        Tag(tag=tags.VER, value=ver),
        Tag(tag=tags.NONC, value=nonce),
        Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_REQUEST)),
    ]

    if public_key is not None:
        tag_list.append(Tag(tag=tags.SRV, value=partial_sha512(b"\xff" + public_key)))

    message = Message(tags=tag_list)
    message.prepare()
    message.debug_print()
    return Packet(message=message)


@dataclass
class LoadedTag:
    tag: int  # uint32
    value: bytes


@dataclass
class Tag:
    tag: int  # uint32
    value: bytes  # uint32, bytes, or nested Message


@dataclass
class Message:
    tags: list[Tag]

    def debug_print(self) -> None:
        for tag in self.tags:
            print(
                f"Tag {tag.tag.to_bytes(4, 'little').decode('ascii', errors='replace')}: {tag.value}"
            )

    def dump(self) -> bytes:
        num_pairs = len(self.tags)
        if num_pairs == 0:
            raise ValueError("Message must contain at least one tag")

        value_blobs: list[bytes] = []
        for tag in self.tags:
            if isinstance(tag.value, int):
                val_data = struct.pack("<I", tag.value)
            elif isinstance(tag.value, bytes):
                val_data = tag.value
            elif isinstance(tag.value, Message):
                val_data = tag.value.dump()
            else:
                raise TypeError("Unsupported tag value type")

            if len(val_data) % 4 != 0:
                raise ValueError(
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
        """Prepares a Roughtime message for sending"""
        self.tags.sort(key=lambda t: t.tag)
        self.zzzz()

    def zzzz(self) -> None:
        # fill the message with a ZZZZ tag to pad until 1024 bytes
        current_size = len(self.dump())
        if current_size >= 1024:
            return  # already at or above 1024 bytes

        zlen = 1024 - current_size
        zzzz_tag = Tag(tag=tags.ZZZZ, value=b"\x00" * zlen)
        self.tags.append(zzzz_tag)

    @classmethod
    def load(cls, data: bytes) -> Message:
        reader = io.BytesIO(data)
        (num_pairs,) = struct.unpack("<I", reader.read(4))
        if num_pairs == 0:
            raise ValueError("Message must contain at least one tag")

        offsets = [0]

        for i in range(num_pairs - 1):
            (offset,) = struct.unpack("<I", reader.read(4))
            offsets.append(offset)

        tags: list[int] = []
        for i in range(num_pairs):
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

    def dump(self) -> bytes:
        message_data = self.message.dump()
        data = struct.pack("<Q", self.magic)
        data += struct.pack("<I", len(message_data))
        data += message_data
        return data

    @classmethod
    def load(cls, data: bytes) -> Packet:
        magic, msg_len = struct.unpack("<QI", data[:12])
        if magic != cls.magic:
            raise ValueError(f"Invalid magic number: {magic:#x}")

        if len(data) < 12 + msg_len:
            raise ValueError("Data too short for declared message length")

        msg_data = data[12 : 12 + msg_len]
        message = Message.load(msg_data)
        return cls(message=message)


def pop_by_predicate(tag_list: list[Tag], predicate: Callable[[Tag], bool]) -> Tag:
    for i, tag in enumerate(tag_list):
        if predicate(tag):
            return tag_list.pop(i)
    raise ValueError("Tag not found matching predicate")


@dataclass
class SignedResponse:
    raw: bytes

    radius: int
    midpoint: int
    version: tuple[int, ...]
    root: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedResponse:
        message = Message.load(data)
        radius_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.RADI)
        midpoint_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.MIDP)
        version_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.VERS)
        root_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.ROOT)

        (radius,) = struct.unpack("<I", radius_tag.value)
        (midpoint,) = struct.unpack("<Q", midpoint_tag.value)
        version = struct.unpack(f"<{len(version_tag.value) // 4}I", version_tag.value)
        root = root_tag.value

        return cls(
            raw=data, radius=radius, midpoint=midpoint, version=version, root=root
        )


@dataclass
class Delegation:
    raw: bytes
    public_key: bytes
    min_time: int
    max_time: int


@dataclass
class Certificate:
    delegation: Delegation
    signature: bytes
    ...

    @classmethod
    def from_bytes(cls, data: bytes) -> Certificate:
        message = Message.load(data)
        dele_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.DELE)
        dele_message = Message.load(dele_tag.value)

        pubk_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.PUBK)
        mint_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.MINT)
        maxt_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.MAXT)

        public_key = pubk_tag.value
        (min_time,) = struct.unpack("<Q", mint_tag.value)
        (max_time,) = struct.unpack("<Q", maxt_tag.value)

        delegation = Delegation(
            raw=dele_tag.value,
            public_key=public_key,
            min_time=min_time,
            max_time=max_time,
        )

        signature_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.SIG)
        signature = signature_tag.value

        return cls(delegation=delegation, signature=signature)


def partial_sha512(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    full_hash = digest.finalize()
    return full_hash[:32]


@dataclass
class Response:
    request: bytes
    """The raw bytes of Roughtime packet that triggered this response"""

    packet: Packet
    """The full Roughtime response packet"""

    signature: bytes
    """The signature over the signed response"""

    nonce: bytes
    """The nonce used in the request/response"""

    type: int
    """The type of the response (should be TYPE_RESPONSE)"""

    path: tuple[int, ...]
    """The PATH tag value from the response. Used for the Merkle tree."""

    signed_response: SignedResponse
    """The parsed signed response"""

    certificate: Certificate
    """The certificate used to derive the public key."""

    index: int
    """The index of the server in the Merkle tree."""

    @classmethod
    def from_packet(cls, *, raw: bytes, request: bytes) -> Response:
        p = Packet.load(raw)

        tag_list = p.message.tags.copy()
        sig = pop_by_predicate(tag_list, lambda t: t.tag == tags.SIG)
        nonc = pop_by_predicate(tag_list, lambda t: t.tag == tags.NONC)
        type = pop_by_predicate(tag_list, lambda t: t.tag == tags.TYPE)
        path = pop_by_predicate(tag_list, lambda t: t.tag == tags.PATH)
        srep = pop_by_predicate(tag_list, lambda t: t.tag == tags.SREP)
        cert = pop_by_predicate(tag_list, lambda t: t.tag == tags.CERT)
        indx = pop_by_predicate(tag_list, lambda t: t.tag == tags.INDX)

        return cls(
            request=request,
            packet=p,
            signature=sig.value,
            nonce=nonc.value,
            type=struct.unpack("<I", type.value)[0],
            path=struct.unpack(f"<{len(path.value) // 4}I", path.value),
            signed_response=SignedResponse.from_bytes(srep.value),
            certificate=Certificate.from_bytes(cert.value),
            index=struct.unpack("<I", indx.value)[0],
        )

    def _verify_merkle(self) -> bool:
        h = partial_sha512(b"\x00" + self.request)

        for i, node in enumerate(self.path):
            node_bytes = struct.pack("<I", node)
            if (self.index >> i) & 1 == 0:
                h = partial_sha512(b"\x01" + node_bytes + h)
            else:
                h = partial_sha512(b"\x01" + h + node_bytes)

        return h == self.signed_response.root

    def verify(self, long_term_public_key_bytes: bytes) -> bool:
        # 5.4. Validity of Response

        # The signature in CERT was made with the long-term key of the server.
        long_term_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            long_term_public_key_bytes
        )
        long_term_public_key.verify(
            self.certificate.signature,
            DELEGATION_CONTEXT_STRING + self.certificate.delegation.raw,
        )

        # The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        midp = self.signed_response.midpoint
        if not (
            self.certificate.delegation.min_time
            <= midp
            <= self.certificate.delegation.max_time
        ):
            raise ValueError("MIDP timestamp is outside of delegation bounds")

        # The INDX and PATH values prove a hash value derived from the request packet was included in the Merkle tree with value ROOT
        if not self._verify_merkle():
            raise ValueError("Merkle tree verification failed")

        # The signature of SREP in SIG validates with the public key in DELE.
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            self.certificate.delegation.public_key
        )
        public_key.verify(
            self.signature, RESPONSE_CONTEXT_STRING + self.signed_response.raw
        )

        return True
