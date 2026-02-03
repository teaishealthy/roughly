from __future__ import annotations

import asyncio
import logging
import os
import string
import struct
import time
from random import SystemRandom
from typing import TYPE_CHECKING, NamedTuple, TypeVar, cast

from cryptography.hazmat.primitives.asymmetric import ed25519

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

from roughly import (
    DELEGATION_CONTEXT_STRING,
    DELEGATION_CONTEXT_STRING_OLD,
    DRAFT_VERSION_ZERO,
    GOOGLE_ROUGHTIME_SENTINEL,
    PACKET_SIZE,
    RESPONSE_CONTEXT_STRING,
    TYPE_FIRST_VERSION,
    Certificate,
    Delegation,
    Message,
    Packet,
    PacketError,
    Response,
    SignedResponse,
    Tag,
    build_supported_versions,
    format_versions,
    partial_sha512,
    pop_by_tag,
    pop_by_tag_optional,
    sha512,
    sha512_256,
    tags,
)

random = SystemRandom()

logger = logging.getLogger(__name__)

T = TypeVar("T")

NONCE_SIZE = 32
VER_7_NONCE_SIZE = 64
MAX_DRAFT_VERSION = 0xFFFFFFFF

DEFAULT_RADIUS = 3
CLIENT_VERSIONS_SUPPORTED = build_supported_versions(10, 15)

CERT_VALIDITY = 60 * 60  # 1 hour

GREASE_PROBABILITY = 0.001


def grease_add_undefined_tag(message: Message) -> Message:
    # undefined tags
    # 4 byte tag name
    tag_name = int.from_bytes(random.choices(string.ascii_uppercase.encode("ascii"), k=4))
    tag_value = os.urandom(random.randint(1, 16) * 4)

    message.tags.append(Tag(tag=tag_name, value=tag_value))
    message.tags.sort(key=lambda t: t.tag)
    return message


def grease_remove_random_tag(message: Message) -> Message:
    if message.tags:
        message.tags.remove(random.choice(message.tags))
    return message


def grease_change_version(message: Message) -> Message:
    # TODO: implement version grease, need to be able to resign packets
    return message


def grease_change_time(message: Message) -> Message:
    srep_raw = pop_by_tag(message.tags, tags.SREP)
    srep = SignedResponse.from_bytes(srep_raw.value)
    # from 0 to uint32 max
    srep.midpoint = random.randint(0, 0x100000000)
    new_srep_raw = srep.to_bytes()
    message.tags.append(Tag(tag=tags.SREP, value=new_srep_raw))
    message.tags.sort(key=lambda t: t.tag)
    return message


GREASERS: list[Callable[[Message], Message]] = [
    grease_add_undefined_tag,
    grease_remove_random_tag,
    grease_change_time,
    grease_change_version,  # TODO: implement
]


def grease_message(message: Message) -> Message:
    greaser = random.choice(GREASERS)
    logger.debug("Applying greaser: %s", greaser.__name__)
    return greaser(message)


class CertificateStore(NamedTuple):
    old: Certificate
    new: Certificate
    google: Certificate
    expiry: int


def draft_version_boundary(
    version: int, *, start: int | None = None, end: int | None = None
) -> int:
    # check if a version is within the draft version range, if so check if its in the given bounds
    # max for draft versions is 0xffffffff
    if DRAFT_VERSION_ZERO < version < MAX_DRAFT_VERSION:
        if start is not None and version < start:
            return False
        return not (end is not None and version > end)
    return False


def generate_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def load_key(data: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(data)


def public_key_bytes(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def srv_hash(key: ed25519.Ed25519PrivateKey) -> bytes:
    return partial_sha512(b"\xff" + public_key_bytes(key))


def create_certificate(  # noqa: PLR0913
    long_term_key: ed25519.Ed25519PrivateKey,
    delegated_key: ed25519.Ed25519PrivateKey,
    min_time: int,
    max_time: int,
    delegation_string: bytes,
    *,
    google: bool | None = None,
) -> Certificate:
    """Create and sign a delegation certificate."""
    # VDIFF: Google Roughtime clients expect time in microseconds
    if google:
        min_time *= 1_000_000
        max_time *= 1_000_000

    return Certificate.signed(
        Delegation(
            min_time=min_time,
            max_time=max_time,
            public_key=public_key_bytes(delegated_key),
        ),
        private_key=long_term_key,
        context_string=delegation_string,
    )


class Server(NamedTuple):
    # not really a "Server", more like a configuration
    long_term_key: ed25519.Ed25519PrivateKey
    delegated_key: ed25519.Ed25519PrivateKey
    certificates: CertificateStore
    validity_seconds: int | None
    radius: int
    versions: tuple[int, ...]
    grease: bool
    grease_probability: float

    @staticmethod
    def get_time() -> int:
        return int(time.time())

    @classmethod
    def create(  # noqa: PLR0913
        cls,
        private_key: bytes | None = None,
        *,
        validity_seconds: int | None = None,
        radius: int = DEFAULT_RADIUS,
        versions: Sequence[int] | None = None,
        grease: bool = False,
        grease_probability: float | None = None,
    ) -> Server:
        cert_validity_seconds = validity_seconds
        if cert_validity_seconds is None:
            cert_validity_seconds = CERT_VALIDITY
        if grease_probability is None:
            grease_probability = GREASE_PROBABILITY

        long_term = load_key(private_key) if private_key else generate_key()
        delegated = generate_key()
        now = cls.get_time()
        expiry = now + cert_validity_seconds

        def make_cert(string: bytes, *, google: bool | None = None) -> Certificate:
            return create_certificate(
                long_term,
                delegated,
                now,
                expiry,
                string,
                google=google,
            )

        certificates = CertificateStore(
            old=make_cert(DELEGATION_CONTEXT_STRING_OLD),
            new=make_cert(DELEGATION_CONTEXT_STRING),
            google=make_cert(DELEGATION_CONTEXT_STRING_OLD, google=True),
            expiry=expiry,
        )

        return cls(
            long_term_key=long_term,
            delegated_key=delegated,
            certificates=certificates,
            validity_seconds=validity_seconds,
            radius=radius,
            versions=tuple(versions or CLIENT_VERSIONS_SUPPORTED),
            grease=grease,
            grease_probability=grease_probability,
        )

    def refresh(self) -> Server:
        return self.create(
            private_key=self.long_term_key.private_bytes_raw(),
            validity_seconds=self.validity_seconds,
            radius=self.radius,
            versions=self.versions,
            grease=self.grease,
            grease_probability=self.grease_probability,
        )


class Request(NamedTuple):
    raw: bytes

    versions: list[int]
    nonce: bytes

    type: int | None
    srv: bytes | None

    @classmethod
    def from_bytes(cls, data: bytes) -> Request:
        packet = Packet.from_bytes(data)
        tag_list = packet.message.tags.copy()

        ver = pop_by_tag_optional(tag_list, tags.VER)
        if ver:
            versions = list(struct.unpack(f"<{len(ver.value) // 4}I", ver.value))
        else:
            versions = [GOOGLE_ROUGHTIME_SENTINEL]

        nonc = pop_by_tag(tag_list, tags.NONC)

        typ = pop_by_tag_optional(tag_list, tags.TYPE)
        type = struct.unpack("<I", typ.value)[0] if typ else None

        srv = pop_by_tag_optional(tag_list, tags.SRV)
        # always an optional tag

        return Request(
            raw=data,
            versions=versions,
            type=type,
            nonce=nonc.value,
            srv=srv.value if srv else None,
        )

    def validate(self, version: int) -> None:
        # VDIFF: Validate according to the Roughtime spec for a given version

        # VDIFF: TYPE tag introduced in draft-14
        if draft_version_boundary(version, start=TYPE_FIRST_VERSION):
            if self.type is None:
                raise PacketError(f"Missing TYPE for version {version}")
            if self.type != tags.TYPE_REQUEST:
                raise PacketError(f"Invalid TYPE {self.type}, expected {tags.TYPE_REQUEST}")

        # VDIFF: NONC size differs in draft-8+
        expected_nonce_size = VER_7_NONCE_SIZE
        if draft_version_boundary(version, start=DRAFT_VERSION_ZERO | 7):
            expected_nonce_size = NONCE_SIZE

        if len(self.nonce) != expected_nonce_size:
            raise PacketError(
                f"Invalid NONC size {len(self.nonce)}, expected {expected_nonce_size}"
            )


def select_version(client: Sequence[int], server: Sequence[int]) -> int | None:
    if GOOGLE_ROUGHTIME_SENTINEL in client:
        return GOOGLE_ROUGHTIME_SENTINEL
    common = set(client) & set(server)
    return max(common) if common else None


def build_merkle_tree(version: int, requests: Sequence[Request]) -> tuple[bytes, list[list[bytes]]]:
    # VDIFF: until draft-8: use sha512_256 for leaves
    hasher = partial_sha512
    if version <= DRAFT_VERSION_ZERO | 7:
        hasher = sha512_256

    # VDIFF: Google Roughtime uses sha512 for leaves
    if version == GOOGLE_ROUGHTIME_SENTINEL:
        hasher = sha512

    leaves: list[bytes] = []

    # VDIFF: until draft-12: leaves are built from nonce, not full request
    for r in requests:
        if draft_version_boundary(version, start=DRAFT_VERSION_ZERO | 12):
            h = hasher(b"\x00" + r.raw)
        else:
            h = hasher(b"\x00" + r.nonce)
        leaves.append(h)

    size = 1
    while size < len(leaves):
        size *= 2
    while len(leaves) < size:
        leaves.append(leaves[-1])

    levels: list[list[bytes]] = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = [
            partial_sha512(b"\x01" + current[i] + current[i + 1]) for i in range(0, len(current), 2)
        ]
        levels.append(next_level)
        current = next_level

    return levels[-1][0], levels


def get_merkle_path(levels: list[list[bytes]], index: int) -> list[bytes]:
    path: list[bytes] = []
    idx = index
    for level in levels[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            path.append(level[sibling])
        idx //= 2
    return path


def build_response(  # noqa: PLR0913
    server: Server,
    *,
    nonce: bytes,
    version: int,
    midpoint: int,
    root: bytes,
    path: list[bytes],
    index: int,
) -> Packet:
    # We very much expect the client to ignore unknown tags
    # we could also be a good programmer and handle versions properly
    # but let's expect clients to be well-built :3

    radius = server.radius
    if version == GOOGLE_ROUGHTIME_SENTINEL:
        # VDIFF: midpoint and radius are in microseconds for Google Roughtime
        midpoint *= 1_000_000
        radius *= 1_000_000

    srep = SignedResponse(
        radius=radius,
        midpoint=midpoint,
        root=root,
        version=version,
        versions=server.versions,
    )

    # VDIFF: in draft-8 through draft-11, the old certificate format is used
    # Google uses a different certificate format as well
    cert = pick_cert(certificates=server.certificates, version=version)

    resp = make_response(server, nonce, version, path, index, srep, cert)
    return Packet(message=resp)


def pick_cert(*, certificates: CertificateStore, version: int) -> Certificate:
    if version == GOOGLE_ROUGHTIME_SENTINEL:
        return certificates.google
    if DRAFT_VERSION_ZERO | 7 < version < DRAFT_VERSION_ZERO | 12:
        return certificates.old
    return certificates.new


def make_response(  # noqa: PLR0913
    server: Server,
    nonce: bytes,
    version: int,
    path: list[bytes],
    index: int,
    srep: SignedResponse,
    cert: Certificate,
) -> Message:
    srep_raw = srep.to_bytes()
    sig = server.delegated_key.sign(RESPONSE_CONTEXT_STRING + srep_raw)

    response = Response(
        signature=sig,
        nonce=nonce,
        type=tags.TYPE_RESPONSE if version != GOOGLE_ROUGHTIME_SENTINEL else None,
        path=path,
        signed_response=srep,
        certificate=cert,
        index=index,
    )

    return response.to_message(version=version)


def handle_request(server: Server, data: bytes) -> bytes | None:
    return handle_batch(server, (data,))[0]


def handle_batch(  # noqa: C901 TODO: refactor this function
    server: Server,
    requests: Sequence[bytes],
) -> list[bytes | None]:
    # TODO(batching): we need to ensure that a batch is compatible
    # i.e. having to pick different hashers would break the merkle tree
    # for now, we don't batch requests at all

    if not requests:
        return []

    expected = srv_hash(server.long_term_key)

    parsed: list[Request | None] = []

    for data in requests:
        try:
            if len(data) < PACKET_SIZE:
                logger.debug("Dropped request that is too small")
                parsed.append(None)
                continue

            req = Request.from_bytes(data)
            ver = select_version(req.versions, server.versions)

            if ver is None:
                logger.debug(
                    "Dropped request with no common version. Got %s, have %s",
                    format_versions(req.versions),
                    format_versions(server.versions),
                )
                parsed.append(None)
                continue

            req.validate(ver)

            if req.srv is not None and req.srv != expected:
                parsed.append(None)
                logger.debug("Dropped request with invalid SRV")
                continue

            parsed.append(req)
        except PacketError:
            logger.exception("Dropped invalid request")
            parsed.append(None)

    # a poem to pyright:
    # you must understand
    # no, you even know.
    # p is typed and so is i
    # now why, oh why,
    # why do you not see
    # that they are not bound to be free (of Any)?

    valid_requests: Sequence[Request] = ()
    valid_idx: Sequence[int] = ()

    pairs = [(p, i) for i, p in enumerate(parsed) if p]
    if pairs:
        valid_requests, valid_idx = zip(*((p, i) for i, p in enumerate(parsed) if p), strict=False)
    else:
        return [None] * len(requests)

    # TODO(batching): see above comment
    version = cast(
        int,
        select_version(
            valid_requests[0].versions,
            server.versions,
        ),
    )

    # we can safely drop failed requests here, i think
    root, levels = build_merkle_tree(version, valid_requests)

    midpoint = server.get_time()
    responses: list[bytes | None] = [None] * len(requests)

    for merkle_idx, (req_id, req) in enumerate(zip(valid_idx, valid_requests, strict=True)):
        path = get_merkle_path(levels, merkle_idx)
        packet = build_response(
            server,
            nonce=req.nonce,
            # TODO(batching): select the right version here
            version=version,
            midpoint=midpoint,
            root=root,
            path=path,
            index=merkle_idx,
        )

        if server.grease and random.random() < server.grease_probability:
            logger.debug("Greasing response for request %d", req_id)
            grease_message(packet.message)

        response = packet.dump(google=(version == GOOGLE_ROUGHTIME_SENTINEL))

        if len(response) > len(req.raw):
            # we drop responses larger than requests to avoid amplification attacks
            logger.debug(
                "Dropping response larger than request (response: %d, request: %d)",
                len(response),
                len(req.raw),
            )
            continue
        responses[req_id] = response

    return responses


class UDPHandler(asyncio.DatagramProtocol):
    def __init__(self, server: Server) -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.server.certificates.expiry < self.server.get_time():
            logger.info("Server key expired, refreshing")
            self.server = self.server.refresh()

        host, port, *_ = addr

        logger.debug("Received datagram from %s:%d", host, port)
        try:
            resp = handle_request(self.server, data)
            if resp and self.transport:
                self.transport.sendto(resp, addr)
                logger.debug("Sent response to %s:%d", host, port)
            else:
                logger.debug("No response sent to %s:%d", host, port)
        except Exception:
            logger.exception("Error handling request from %s:%d", host, port)


async def serve(
    server: Server,
    host: str = "0.0.0.0",  # noqa: S104
    port: int = 2002,
    handler: type[UDPHandler] = UDPHandler,
) -> None:
    """Start a Roughtime server.

    Args:
        server (Server): The server to run.
        port (int, optional): The port to listen on. Defaults to 2002.
        host (str, optional): The host to bind to. Defaults to "0.0.0.0"
        handler (type[UDPHandler], optional): The UDP handler class to use. Defaults to UDPHandler.
    """
    transport = await _start_server(server, host, port, handler)

    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


async def _start_server(
    server: Server,
    host: str,
    port: int,
    handler: type[UDPHandler],
    *,
    loop: asyncio.AbstractEventLoop | None = None,
) -> asyncio.DatagramTransport:
    if not loop:
        loop = asyncio.get_running_loop()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: handler(server), local_addr=(host, port)
    )
    logger.info("Listening on %s:%d", host, port)
    logger.debug(
        "Running with supported versions: %s + Google Roughtime", format_versions(server.versions)
    )

    return transport
