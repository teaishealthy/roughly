from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import NamedTuple, cast

from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import (
    DELEGATION_CONTEXT_STRING,
    DELEGATION_CONTEXT_STRING_OLD,
    DRAFT_VERSION_ZERO,
    PACKET_SIZE,
    RESPONSE_CONTEXT_STRING,
    TYPE_FIRST_VERSION,
    Message,
    Packet,
    PacketError,
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

logger = logging.getLogger(__name__)

# The actual value is not important, we just need a unique sentinel
# that doesn't make sense semantically
GOOGLE_ROUGHTIME_SENTINEL = int.from_bytes(b"Google Roughtime")

NONCE_SIZE = 32
VER_7_NONCE_SIZE = 64
MAX_DRAFT_VERSION = 0xFFFFFFFF

DEFAULT_RADIUS = int(os.environ.get("ROUGHLY_DEFAULT_RADIUS", "3"))
CLIENT_VERSIONS_SUPPORTED = build_supported_versions(10, 15)

CERT_VALIDITY = 60 * 60  # 1 hour


class CertificateStore(NamedTuple):
    old: bytes
    new: bytes
    google: bytes
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
) -> bytes:
    """Create and sign a delegation certificate. Returns raw CERT message bytes."""
    # VDIFF: Google Roughtime clients expect time in microseconds
    if google:
        min_time *= 1_000_000
        max_time *= 1_000_000

    dele = Message(
        tags=[
            Tag(tag=tags.MINT, value=struct.pack("<Q", min_time)),
            Tag(tag=tags.MAXT, value=struct.pack("<Q", max_time)),
            Tag(tag=tags.PUBK, value=public_key_bytes(delegated_key)),
        ]
    )
    dele.tags.sort(key=lambda t: t.tag)
    dele_raw = dele.dump()

    sig = long_term_key.sign(delegation_string + dele_raw)

    cert = Message(tags=[Tag(tag=tags.DELE, value=dele_raw), Tag(tag=tags.SIG, value=sig)])
    cert.tags.sort(key=lambda t: t.tag)
    return cert.dump()


class Server(NamedTuple):
    # not really a "Server", more like a configuration
    long_term_key: ed25519.Ed25519PrivateKey
    delegated_key: ed25519.Ed25519PrivateKey
    certificates: CertificateStore
    validity_seconds: int | None
    radius: int
    versions: tuple[int, ...]

    @staticmethod
    def get_time() -> int:
        return int(time.time())

    @classmethod
    def create(
        cls,
        private_key: bytes | None = None,
        *,
        validity_seconds: int | None = None,
        radius: int = DEFAULT_RADIUS,
        versions: tuple[int, ...] | None = None,
    ) -> Server:
        cert_validity_seconds = validity_seconds
        if cert_validity_seconds is None:
            cert_validity_seconds = CERT_VALIDITY

        long_term = load_key(private_key) if private_key else generate_key()
        delegated = generate_key()
        now = cls.get_time()
        expiry = now + cert_validity_seconds

        def make_cert(string: bytes, *, google: bool | None = None) -> bytes:
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
            versions=versions or CLIENT_VERSIONS_SUPPORTED,
        )

    def refresh(self) -> Server:
        return self.create(
            private_key=self.long_term_key.private_bytes_raw(),
            validity_seconds=self.validity_seconds,
            radius=self.radius,
            versions=self.versions,
        )


class Request(NamedTuple):
    raw: bytes

    versions: list[int]
    nonce: bytes

    type: int | None
    srv: bytes | None

    @classmethod
    def from_bytes(cls, data: bytes) -> Request:
        packet = Packet.load(data)
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


def select_version(client: list[int], server: tuple[int, ...]) -> int | None:
    if GOOGLE_ROUGHTIME_SENTINEL in client:
        return GOOGLE_ROUGHTIME_SENTINEL
    common = set(client) & set(server)
    return max(common) if common else None


def build_merkle_tree(
    version: int, requests: tuple[Request, ...]
) -> tuple[bytes, list[list[bytes]]]:
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
) -> bytes:
    # We very much expect the client to ignore unknown tags
    # we could also be a good programmer and handle versions properly
    # but let's expect clients to be well-built :3

    radius = server.radius
    if version == GOOGLE_ROUGHTIME_SENTINEL:
        # VDIFF: midpoint and radius are in microseconds for Google Roughtime
        midpoint *= 1_000_000
        radius *= 1_000_000

    srep = Message(
        tags=[
            Tag(tag=tags.RADI, value=struct.pack("<I", radius)),
            Tag(tag=tags.MIDP, value=struct.pack("<Q", midpoint)),
            Tag(tag=tags.ROOT, value=root),
        ]
    )
    # VDIFF: we can't pack GOOGLE_ROUGHTIME_SENTINEL as a u32
    # vroughtime clients expect no VER/VERS tags at all
    if version != GOOGLE_ROUGHTIME_SENTINEL:
        srep.tags.append(Tag(tag=tags.VER, value=struct.pack("<I", version)))
        srep.tags.append(
            Tag(tag=tags.VERS, value=b"".join(struct.pack("<I", v) for v in server.versions))
        )

    srep.tags.sort(key=lambda t: t.tag)
    srep_raw = srep.dump()

    sig = server.delegated_key.sign(RESPONSE_CONTEXT_STRING + srep_raw)

    # VDIFF: in draft-8 throught draft-11, the old certificate format is used
    # Google uses a different certificate format as well
    cert = server.certificates.new
    if DRAFT_VERSION_ZERO | 7 < version < DRAFT_VERSION_ZERO | 12:
        cert = server.certificates.old

    if version == GOOGLE_ROUGHTIME_SENTINEL:
        cert = server.certificates.google

    resp = Message(
        tags=[
            Tag(tag=tags.SIG, value=sig),
            Tag(tag=tags.NONC, value=nonce),
            Tag(tag=tags.PATH, value=b"".join(path)),
            Tag(tag=tags.SREP, value=srep_raw),
            Tag(tag=tags.CERT, value=cert),
            Tag(tag=tags.INDX, value=struct.pack("<I", index)),
        ]
    )
    # VDIFF: vroughtime issue
    if version != GOOGLE_ROUGHTIME_SENTINEL:
        resp.tags.append(Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_RESPONSE)))

    if version <= DRAFT_VERSION_ZERO | 11:
        resp.tags.append(Tag(tag=tags.VER, value=struct.pack("<I", version)))

    resp.tags.sort(key=lambda t: t.tag)
    return Packet(message=resp).dump(google=(version == GOOGLE_ROUGHTIME_SENTINEL))


def handle_request(server: Server, data: bytes) -> bytes | None:
    return handle_batch(server, (data,))[0]


def handle_batch(server: Server, requests: tuple[bytes]) -> list[bytes | None]:
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

    valid_requests: tuple[Request, ...] = ()
    valid_idx: tuple[int, ...] = ()

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
        response = build_response(
            server,
            nonce=req.nonce,
            # TODO(batching): select the right version here
            version=version,
            midpoint=midpoint,
            root=root,
            path=path,
            index=merkle_idx,
        )
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
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: handler(server), local_addr=(host, port)
    )
    logger.info("Listening on %s:%d", host, port)
    logger.debug(
        "Running with supported versions: %s + Google Roughtime", format_versions(server.versions)
    )

    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
