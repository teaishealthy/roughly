"""Roughtime protocol implementation in Python."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

import cryptography.exceptions
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import tags

if TYPE_CHECKING:
    from collections.abc import Callable

PACKET_SIZE = 1024

MJD_UNIX_EPOCH = 40587
SECONDS_IN_A_DAY = 86400

ROUGHTIM = 0x4D49544847554F52
RESPONSE_CONTEXT_STRING = b"RoughTime v1 response signature\x00"
DELEGATION_CONTEXT_STRING = b"RoughTime v1 delegation signature\x00"
DELEGATION_CONTEXT_STRING_OLD = b"RoughTime v1 delegation signature--\x00"

RoughtimeErrorReason = Literal["merkle", "key-age", "signature-certificate", "signature-response"]

logger = logging.getLogger(__name__)


class RoughtimeError(Exception):
    """Represents a generic Roughtime error."""


class PacketError(RoughtimeError):
    """Represents an error in packet parsing."""


class FormatError(RoughtimeError):
    """Represents an error in packet formatting."""


class VerificationError(RoughtimeError):
    """Represents an error in response verification."""

    def __init__(self, message: str, *, reason: RoughtimeErrorReason) -> None:
        super().__init__(message)
        self.reason: RoughtimeErrorReason = reason


def build_supported_versions(start: int, end: int) -> tuple[int, ...]:
    # Build a tuple of supported Roughtime versions (inclusive of start and end)
    versions = (1, *tuple(2147483648 | v for v in range(start, end + 1)))
    return tuple(sorted(versions))


VERSIONS_SUPPORTED = build_supported_versions(7, 15)


class QueueDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.transport: asyncio.DatagramTransport | None = None
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]] | Exception] = asyncio.Queue()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        self.queue.put_nowait(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            self.queue.put_nowait(exc)
        self.queue.put_nowait(RoughtimeError("Connection closed unexpectedly"))

    async def recv(self) -> bytes:
        item = await self.queue.get()
        if isinstance(item, Exception):
            raise item
        return item[0]


async def open_udp_socket(host: str, port: int):  # noqa: ANN201
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: QueueDatagramProtocol(loop),
        remote_addr=(host, port),
    )
    return transport, protocol


async def send_request(
    host: str,
    port: int,
    public_key: bytes,
    *,
    versions: tuple[int, ...] | None = None,
    nonce: bytes | None = None,
) -> Response:
    response = await very_dangerously_send_request_and_do_not_verify(
        host,
        port,
        public_key,
        versions=versions,
        nonce=nonce,
    )
    response.verify(public_key)
    logger.debug("Verified response from %s:%d", host, port)
    return response


async def very_dangerously_send_request_and_do_not_verify(
    host: str,
    port: int,
    public_key: bytes | None = None,
    *,
    versions: tuple[int, ...] | None = None,
    nonce: bytes | None = None,
) -> Response:
    """As should be clear from the function name, this function sends a Roughtime request
    but does NOT verify the response in any way. This is dangerous and should only be used
    if you REALLY know what you're doing."""  # noqa: D205 D209
    logger.debug(
        "Sending request to %s:%d with versions=%s",
        host,
        port,
        ", ".join(f"{v:#x}" for v in versions) if versions else "default",
    )
    transport, protocol = await open_udp_socket(host, port)
    logger.debug("Opened UDP socket to %s:%d", host, port)

    try:
        p = build_request(versions=versions, public_key=public_key, nonce=nonce)
        payload = p.dump()
        transport.sendto(payload)
        logger.debug("Sent request to %s:%d", host, port)

        data = await protocol.recv()
        logger.debug("Received %d bytes from %s:%d", len(data), host, port)
        response = Response.from_packet(raw=data, request=payload)
        logger.debug("Parsed (unverified) response from %s:%d", host, port)
    finally:
        transport.close()

    return response


def build_request(
    versions: tuple[int, ...] | None = None,
    public_key: bytes | None = None,
    nonce: bytes | None = None,
) -> Packet:
    """Build a spec-compliant request padded to 1024 bytes (UDP)."""
    if versions is None:
        versions = VERSIONS_SUPPORTED

    ver = b"".join(struct.pack("<I", v) for v in versions)  # VER: uint32 list

    if nonce is None:
        nonce = os.urandom(32)

    tag_list: list[Tag] = [
        Tag(tag=tags.VER, value=ver),
        Tag(tag=tags.NONC, value=nonce),
        Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_REQUEST)),
    ]

    if public_key is not None:
        tag_list.append(Tag(tag=tags.SRV, value=partial_sha512(b"\xff" + public_key)))

    message = Message(tags=tag_list)
    message.prepare()
    return Packet(message=message)


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

    def dump(self) -> bytes:
        num_pairs = len(self.tags)
        if num_pairs == 0:
            raise FormatError("Message must contain at least one tag")

        value_blobs: list[bytes] = []
        for tag in self.tags:
            if isinstance(tag.value, int):
                val_data = struct.pack("<I", tag.value)
            elif isinstance(tag.value, bytes):
                val_data = tag.value
            elif isinstance(tag.value, Message):
                val_data = tag.value.dump()
            else:
                raise FormatError("Unsupported tag value type")

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
        current_size = len(self.dump())
        if current_size >= PACKET_SIZE:
            return  # already at or above 1024 bytes

        zzzz_tag = Tag(tag=tags.ZZZZ, value=b"")
        self.tags.append(zzzz_tag)

        current_size = len(Packet(message=self).dump())

        zlen = PACKET_SIZE - current_size
        zzzz_tag.value = b"\x00" * zlen

    @classmethod
    def load(cls, data: bytes) -> Message:
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
            raise PacketError(f"Expected magic {cls.magic:#x}, got {magic:#x}")

        if len(data) < 12 + msg_len:
            raise PacketError("Packet data is shorter than declared message length")

        msg_data = data[12 : 12 + msg_len]
        message = Message.load(msg_data)
        return cls(message=message)


def pop_by_predicate(tag_list: list[Tag], predicate: Callable[[Tag], bool]) -> Tag:
    result = find_by_predicate(tag_list, predicate)
    if result is not None:
        return tag_list.pop(result)
    raise RoughtimeError("Tag not found matching predicate")


def pop_by_predicate_optional(tag_list: list[Tag], predicate: Callable[[Tag], bool]) -> Tag | None:
    result = find_by_predicate(tag_list, predicate)
    if result is not None:
        return tag_list.pop(result)
    return None


def find_by_predicate(tag_list: list[Tag], predicate: Callable[[Tag], bool]) -> int | None:
    for i, tag in enumerate(tag_list):
        if predicate(tag):
            return i
    return None


def split_into_chunks(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def convert_mjd_to_unix(mjd: int) -> int:
    mjd_days = mjd >> 40
    microseconds = mjd & 0xFFFFFFFFFF
    return (mjd_days - MJD_UNIX_EPOCH) * SECONDS_IN_A_DAY + microseconds_to_seconds(microseconds)


def microseconds_to_seconds(microseconds: int) -> int:
    return microseconds // 1_000_000


@dataclass
class SignedResponse:
    raw: bytes

    radius: int
    midpoint: int
    version: int
    versions: tuple[int, ...]
    root: bytes

    @classmethod
    def from_bytes(cls, data: bytes, *, draft7: bool = False) -> SignedResponse:
        message = Message.load(data)
        radius_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.RADI)
        midpoint_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.MIDP)
        versions_tag = pop_by_predicate_optional(message.tags, lambda t: t.tag == tags.VERS)
        version_tag = pop_by_predicate_optional(message.tags, lambda t: t.tag == tags.VER)
        root_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.ROOT)

        (radius,) = struct.unpack("<I", radius_tag.value)
        (midpoint,) = struct.unpack("<Q", midpoint_tag.value)
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
            raw=data,
            radius=radius,
            midpoint=midpoint,
            versions=versions,
            version=version,
            root=root,
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

    @classmethod
    def from_bytes(cls, data: bytes, *, draft7: bool = False) -> Certificate:
        message = Message.load(data)
        dele_tag = pop_by_predicate(message.tags, lambda t: t.tag == tags.DELE)
        dele_message = Message.load(dele_tag.value)

        pubk_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.PUBK)
        mint_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.MINT)
        maxt_tag = pop_by_predicate(dele_message.tags, lambda t: t.tag == tags.MAXT)

        public_key = pubk_tag.value
        (min_time,) = struct.unpack("<Q", mint_tag.value)
        (max_time,) = struct.unpack("<Q", maxt_tag.value)

        if draft7:
            min_time = convert_mjd_to_unix(min_time)
            max_time = convert_mjd_to_unix(max_time)

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


def sha512_256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA512_256())
    digest.update(data)
    return digest.finalize()


@dataclass
class Response:
    raw: bytes
    """The raw bytes of the Roughtime response packet"""

    request: bytes
    """The raw bytes of Roughtime packet that triggered this response"""

    packet: Packet
    """The full Roughtime response packet"""

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

    @property
    def version(self) -> int:
        """The version of the response."""
        if not self.signed_response.version:
            result = find_by_predicate(self.packet.message.tags, lambda t: t.tag == tags.VER)
            if result is None:
                raise PacketError("No VER tag found in response packet")
            (version,) = struct.unpack("<I", self.packet.message.tags[result].value[:4])
            return version

        return self.signed_response.version

    @classmethod
    def from_packet(cls, *, raw: bytes, request: bytes) -> Response:
        p = Packet.load(raw)

        tag_list = p.message.tags.copy()
        sig = pop_by_predicate(tag_list, lambda t: t.tag == tags.SIG)
        nonc = pop_by_predicate(tag_list, lambda t: t.tag == tags.NONC)

        type = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.TYPE)
        if type is not None:
            (type,) = struct.unpack("<I", type.value)

            if type != tags.TYPE_RESPONSE:
                raise PacketError(f"Expected TYPE_RESPONSE, got {type}")

        path = pop_by_predicate(tag_list, lambda t: t.tag == tags.PATH)
        srep = pop_by_predicate(tag_list, lambda t: t.tag == tags.SREP)
        cert = pop_by_predicate(tag_list, lambda t: t.tag == tags.CERT)
        indx = pop_by_predicate(tag_list, lambda t: t.tag == tags.INDX)

        draft7 = False
        maybe_ver = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.VER)
        if maybe_ver is not None:
            (maybe_ver,) = struct.unpack("<I", maybe_ver.value)

            if maybe_ver == 0x80000000 + 7:
                draft7 = True

        response = cls(
            raw=raw,
            request=request,
            packet=p,
            signature=sig.value,
            nonce=nonc.value,
            type=type,
            path=split_into_chunks(path.value, 4),
            signed_response=SignedResponse.from_bytes(srep.value, draft7=draft7),
            certificate=Certificate.from_bytes(cert.value, draft7=draft7),
            index=struct.unpack("<I", indx.value)[0],
        )

        if response.version >= 0x80000000 + 14 and type is None:
            raise PacketError("TYPE tag missing in draft-14+ response")

        return response

    def _verify_merkle(self) -> bool:
        hasher = partial_sha512
        if self.version <= 0x80000000 + 7:
            hasher = sha512_256

        if self.version >= 0x80000000 + 12:
            h = hasher(b"\x00" + self.request)
        else:
            h = hasher(b"\x00" + self.nonce)

        for i, node in enumerate(self.path):
            if (self.index >> i) & 1 == 0:
                h = hasher(b"\x01" + node + h)
            else:
                h = hasher(b"\x01" + h + node)

        return h == self.signed_response.root

    def verify(self, long_term_public_key_bytes: bytes) -> bool:
        delegation_context_string = DELEGATION_CONTEXT_STRING

        # what? the context string got changed in draft-8 through draft-11
        # and then got changed back in draft-12
        if 0x80000000 + 7 < self.version < 0x80000000 + 12:
            delegation_context_string = DELEGATION_CONTEXT_STRING_OLD

        # 5.4. Validity of Response

        # The signature in CERT was made with the long-term key of the server.
        long_term_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            long_term_public_key_bytes
        )
        try:
            long_term_public_key.verify(
                self.certificate.signature,
                delegation_context_string + self.certificate.delegation.raw,
            )
        except cryptography.exceptions.InvalidSignature as e:
            raise VerificationError(
                "Certificate signature invalid", reason="signature-certificate"
            ) from e

        # The MIDP timestamp lies in the interval specified by the MINT and MAXT timestamps.
        midp = self.signed_response.midpoint
        if not (
            self.certificate.delegation.min_time <= midp <= self.certificate.delegation.max_time
        ):
            raise VerificationError(
                "MIDP timestamp is outside of delegation bounds", reason="key-age"
            )

        # The INDX and PATH values prove a hash value derived from the request packet was
        # included in the Merkle tree with value ROOT
        if not self._verify_merkle():
            raise VerificationError("Merkle tree verification failed", reason="merkle")

        # The signature of SREP in SIG validates with the public key in DELE.
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            self.certificate.delegation.public_key
        )
        try:
            public_key.verify(self.signature, RESPONSE_CONTEXT_STRING + self.signed_response.raw)
        except cryptography.exceptions.InvalidSignature as e:
            raise VerificationError(
                "Response signature invalid", reason="signature-response"
            ) from e

        return True
