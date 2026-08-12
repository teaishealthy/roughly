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
    LAST_TOP_LEVEL_VER_VERSION,
    RESPONSE_CONTEXT_STRING,
    VERSIONS_SUPPORTED,
    ProtocolProfile,
    find_by_tag,
    format_versions,
    get_by_tag,
    is_draft_version,
    partial_sha512,
    unpack_uint32,
    unpack_uint32_list,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


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


def offered_versions(packet: Packet) -> tuple[int, ...]:
    """The version space the client offered in its request."""
    if not packet.framed:
        return (GOOGLE_ROUGHTIME_SENTINEL,)

    ver = find_by_tag(packet.message.tags, tags.VER)
    if ver is None:
        raise PacketError("No VER tag found in request packet")
    return unpack_uint32_list(ver.value, what="VER")


def _signed_version(message: Message) -> int | None:
    """The version from SREP, which is covered by the response signature."""
    srep = find_by_tag(message.tags, tags.SREP)
    if srep is None:
        raise PacketError("No SREP tag found in response packet")

    ver = find_by_tag(Message.from_bytes(srep.value).tags, tags.VER)
    if ver is None:
        return None
    return unpack_uint32(ver.value, what="SREP VER")


def resolve_response_version(packet: Packet, *, offered: Sequence[int]) -> int:
    """Determine the version of a response, from the packet structure outwards.

    The version is taken from the signed SREP VER where present, and only otherwise from the
    unsigned top-level VER, which bounds the version to what could have put it there. The
    result must be one of the versions the client offered.
    """
    if not packet.framed:
        version = GOOGLE_ROUGHTIME_SENTINEL
    else:
        signed_version = _signed_version(packet.message)

        top_level = find_by_tag(packet.message.tags, tags.VER)
        top_level_version = (
            unpack_uint32(top_level.value, what="VER") if top_level is not None else None
        )

        if signed_version is not None:
            if top_level_version is not None and top_level_version != signed_version:
                raise PacketError(
                    f"Top-level VER {top_level_version:#x} contradicts "
                    f"the signed SREP VER {signed_version:#x}"
                )
            version = signed_version
        elif top_level_version is not None:
            # VER moved into SREP in draft-12, so anything that puts it at the top level
            # of a response is draft-11 or older.
            if (
                not is_draft_version(top_level_version)
                or top_level_version > LAST_TOP_LEVEL_VER_VERSION
            ):
                raise PacketError(
                    f"Version {top_level_version:#x} must not be signalled by a top-level VER"
                )
            version = top_level_version
        else:
            raise PacketError("Response declares no version")

    if version not in offered:
        if version == GOOGLE_ROUGHTIME_SENTINEL:
            raise PacketError("Response is unframed (Google Roughtime), which was not offered")
        raise PacketError(
            f"Response version {version:#x} not in request VER list: {format_versions(offered)}"
        )

    return version


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

    _version: int

    @property
    def version(self) -> int:
        """The version of the response, as declared on the wire."""
        return self._version

    @classmethod
    def from_packet(cls, *, raw: bytes, request: bytes) -> VerifiableResponse:
        p = Packet.from_bytes(raw)
        request_packet = Packet.from_bytes(request)

        version = resolve_response_version(p, offered=offered_versions(request_packet))
        profile = ProtocolProfile.from_version(version)

        response, dele_raw, srep_raw = Response.from_message(p.message, profile=profile)

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
            _profile=profile,
            _version=version,
        )

        if profile.type_tag_required and response.type is None:
            raise PacketError("TYPE tag missing in response")

        nonc = get_by_tag(request_packet.message.tags, tags.NONC)
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

    def verify(self, long_term_public_key_bytes: bytes) -> bool:  # noqa: C901
        delegation_context_string = self._profile.delegation_context

        # 5.4. Validity of Response

        # Structural checks on the signed response (§5.2.5).
        srep = self.signed_response

        # §5.2.5 L691: RADI MUST NOT be zero.
        if srep.radius == 0:
            raise VerificationError("RADI must not be zero", reason="radius")

        # §5.2.5 L701-704: VERS structure (skip Google profile, which has no VERS tag).
        if srep.versions:
            if len(srep.versions) > 32:  # noqa: PLR2004
                raise VerificationError(
                    f"VERS contains {len(srep.versions)} entries (max 32)",
                    reason="versions",
                )
            for prev, curr in zip(srep.versions, srep.versions[1:], strict=False):
                if curr <= prev:
                    raise VerificationError(
                        "VERS must be strictly ascending and unique",
                        reason="versions",
                    )
            if srep.version not in srep.versions:
                raise VerificationError(
                    f"VERS does not contain the response version {srep.version:#x}",
                    reason="versions",
                )

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
