from __future__ import annotations

import asyncio
import logging
import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

import cryptography.exceptions
from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import tags
from roughly.errors import PacketError, RoughtimeError, VerificationError
from roughly.models import (
    Message,
    Packet,
    Response,
    Tag,
)
from roughly.shared import (
    GOOGLE_ROUGHTIME_SENTINEL,
    RESPONSE_CONTEXT_STRING,
    VERSIONS_SUPPORTED,
    ProtocolProfile,
    find_by_predicate,
    partial_sha512,
    pop_by_tag,
)

if TYPE_CHECKING:
    from collections.abc import Iterable


T = TypeVar("T")


logger = logging.getLogger(__name__)


class QueueDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
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
        QueueDatagramProtocol,
        remote_addr=(host, port),
    )
    return transport, protocol


async def send_request(
    host: str,
    port: int,
    public_key: bytes,
    *,
    versions: Iterable[int] | None = None,
    nonce: bytes | None = None,
) -> VerifiableResponse:
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
    versions: Iterable[int] | None = None,
    nonce: bytes | None = None,
) -> VerifiableResponse:
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
        response = VerifiableResponse.from_packet(raw=data, request=payload)
        logger.debug("Parsed (unverified) response from %s:%d", host, port)
    finally:
        transport.close()

    return response


def build_request(
    versions: Iterable[int] | None = None,
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
class VerifiableResponse(Response):
    """Client-side response with verification context."""

    raw: bytes
    """The raw bytes of the Roughtime response packet"""

    request: bytes
    """The raw bytes of Roughtime packet that triggered this response"""

    packet: Packet
    """The full Roughtime response packet"""

    dele_raw: bytes
    """The raw DELE tag bytes for signature verification"""

    srep_raw: bytes
    """The raw SREP tag bytes for signature verification"""

    _profile: ProtocolProfile

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
    def from_packet(cls, *, raw: bytes, request: bytes) -> VerifiableResponse:
        p = Packet.from_bytes(raw)

        ver_result = find_by_predicate(p.message.tags, lambda t: t.tag == tags.VER)
        if ver_result is not None:
            (wire_ver,) = struct.unpack("<I", p.message.tags[ver_result].value)
        else:
            wire_ver = GOOGLE_ROUGHTIME_SENTINEL
        wire_profile = ProtocolProfile.from_version(wire_ver)

        response, dele_raw, srep_raw = Response.from_message(p.message, profile=wire_profile)

        verifiable = cls(
            signature=response.signature,
            nonce=response.nonce,
            type=response.type,
            path=response.path,
            signed_response=response.signed_response,
            certificate=response.certificate,
            index=response.index,
            raw=raw,
            request=request,
            packet=p,
            dele_raw=dele_raw,
            srep_raw=srep_raw,
            _profile=wire_profile,
        )
        verifiable._profile = ProtocolProfile.from_version(verifiable.version)

        if wire_profile.type_tag_required and response.type is None:
            raise PacketError("TYPE tag missing in response")

        request_message = Packet.from_bytes(request).message
        vers = pop_by_tag(request_message.tags, tags.VER)
        versions = struct.unpack(f"<{len(vers.value) // 4}I", vers.value)
        if verifiable.version not in versions:
            raise PacketError(
                f"Response version {verifiable.version:#x} not in request VER list: "
                + ", ".join(f"{v:#x}" for v in versions)
            )

        nonc = pop_by_tag(request_message.tags, tags.NONC)
        if verifiable.nonce != nonc.value:
            raise PacketError("Response NONC does not match request NONC")

        return verifiable

    def _verify_merkle(self) -> bool:
        raw = self.request if self._profile.leaf_from_request else self.nonce
        h = self._profile.hasher(b"\x00" + raw)

        for i, node in enumerate(self.path):
            if (self.index >> i) & 1 == 0:
                h = self._profile.hasher(b"\x01" + h + node)
            else:
                h = self._profile.hasher(b"\x01" + node + h)

        return h == self.signed_response.root

    def verify(self, long_term_public_key_bytes: bytes) -> bool:
        delegation_context_string = self._profile.delegation_context

        # 5.4. Validity of Response

        # The signature in CERT was made with the long-term key of the server.
        long_term_public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            long_term_public_key_bytes
        )
        try:
            long_term_public_key.verify(
                self.certificate.signature,
                delegation_context_string + self.dele_raw,
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
            public_key.verify(self.signature, RESPONSE_CONTEXT_STRING + self.srep_raw)
        except cryptography.exceptions.InvalidSignature as e:
            raise VerificationError(
                "Response signature invalid", reason="signature-response"
            ) from e

        return True
