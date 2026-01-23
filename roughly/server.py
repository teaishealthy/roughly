from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import (
    DELEGATION_CONTEXT_STRING,
    RESPONSE_CONTEXT_STRING,
    SECONDS_IN_A_DAY,
    Message,
    Packet,
    PacketError,
    Tag,
    build_supported_versions,
    partial_sha512,
    pop_by_predicate_optional,
    tags,
)

logger = logging.getLogger(__name__)

NONCE_SIZE = 32
DEFAULT_RADIUS = int(os.environ.get("ROUGHLY_DEFAULT_RADIUS", "3"))
CLIENT_VERSIONS_SUPPORTED = build_supported_versions(12, 15)
# TODO: Check if the lower version bound can be lowered.


def generate_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def load_key(data: bytes) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(data)


def public_key_bytes(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def srv_hash(key: ed25519.Ed25519PrivateKey) -> bytes:
    return partial_sha512(b"\xff" + public_key_bytes(key))


def create_certificate(
    long_term_key: ed25519.Ed25519PrivateKey,
    delegated_key: ed25519.Ed25519PrivateKey,
    min_time: int,
    max_time: int,
) -> bytes:
    """Create and sign a delegation certificate. Returns raw CERT message bytes."""
    dele = Message(
        tags=[
            Tag(tag=tags.MINT, value=struct.pack("<Q", min_time)),
            Tag(tag=tags.MAXT, value=struct.pack("<Q", max_time)),
            Tag(tag=tags.PUBK, value=public_key_bytes(delegated_key)),
        ]
    )
    dele.tags.sort(key=lambda t: t.tag)
    dele_raw = dele.dump()

    sig = long_term_key.sign(DELEGATION_CONTEXT_STRING + dele_raw)

    cert = Message(tags=[Tag(tag=tags.DELE, value=dele_raw), Tag(tag=tags.SIG, value=sig)])
    cert.tags.sort(key=lambda t: t.tag)
    return cert.dump()


class Server(NamedTuple):
    # not really a "Server", more like a configuration
    long_term_key: ed25519.Ed25519PrivateKey
    delegated_key: ed25519.Ed25519PrivateKey
    cert_raw: bytes
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
        validity_seconds: int = SECONDS_IN_A_DAY * 30,
        radius: int = DEFAULT_RADIUS,
        versions: tuple[int, ...] | None = None,
    ) -> Server:
        long_term = load_key(private_key) if private_key else generate_key()
        delegated = generate_key()
        now = cls.get_time()
        cert = create_certificate(long_term, delegated, now - 60, now + validity_seconds)
        return cls(
            long_term,
            delegated,
            cert,
            radius,
            versions or CLIENT_VERSIONS_SUPPORTED,
        )


class Request(NamedTuple):
    raw: bytes
    versions: list[int]
    nonce: bytes
    srv: bytes | None

    @classmethod
    def from_bytes(cls, data: bytes) -> Request:
        packet = Packet.load(data)
        tag_list = packet.message.tags.copy()

        ver = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.VER)
        if not ver:
            raise PacketError("Missing VER")
        versions = list(struct.unpack(f"<{len(ver.value) // 4}I", ver.value))

        nonc = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.NONC)
        if not nonc or len(nonc.value) != NONCE_SIZE:
            raise PacketError("Missing or invalid NONC")

        typ = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.TYPE)
        if not typ or struct.unpack("<I", typ.value)[0] != tags.TYPE_REQUEST:
            raise PacketError("Missing or invalid TYPE")

        srv = pop_by_predicate_optional(tag_list, lambda t: t.tag == tags.SRV)
        return Request(data, versions, nonc.value, srv.value if srv else None)


def select_version(client: list[int], server: tuple[int, ...]) -> int | None:
    common = set(client) & set(server)
    return max(common) if common else None


def build_merkle_tree(packets: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    leaves = [partial_sha512(b"\x00" + p) for p in packets]

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
    srep = Message(
        tags=[
            Tag(tag=tags.VER, value=struct.pack("<I", version)),
            Tag(tag=tags.RADI, value=struct.pack("<I", server.radius)),
            Tag(tag=tags.MIDP, value=struct.pack("<Q", midpoint)),
            Tag(tag=tags.VERS, value=b"".join(struct.pack("<I", v) for v in server.versions)),
            Tag(tag=tags.ROOT, value=root),
        ]
    )
    srep.tags.sort(key=lambda t: t.tag)
    srep_raw = srep.dump()

    sig = server.delegated_key.sign(RESPONSE_CONTEXT_STRING + srep_raw)

    resp = Message(
        tags=[
            Tag(tag=tags.SIG, value=sig),
            Tag(tag=tags.NONC, value=nonce),
            Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_RESPONSE)),
            Tag(tag=tags.PATH, value=b"".join(path)),
            Tag(tag=tags.SREP, value=srep_raw),
            Tag(tag=tags.CERT, value=server.cert_raw),
            Tag(tag=tags.INDX, value=struct.pack("<I", index)),
        ]
    )
    resp.tags.sort(key=lambda t: t.tag)
    return Packet(message=resp).dump()


def handle_request(server: Server, data: bytes) -> bytes | None:
    return handle_batch(server, [data])[0]


def handle_batch(server: Server, requests: list[bytes]) -> list[bytes | None]:
    if not requests:
        return []

    expected = srv_hash(server.long_term_key)
    parsed: list[tuple[int, Request] | None] = []

    for data in requests:
        try:
            req = Request.from_bytes(data)
            if req.srv and req.srv != expected:
                parsed.append(None)
                logger.debug("Dropped request with invalid SRV")
                continue
            ver = select_version(req.versions, server.versions)
            if ver is None:
                logger.debug("Dropped request with no common version")
                parsed.append(None)
                continue
            parsed.append((ver, req))
        except PacketError:
            logger.exception("Dropped invalid request")
            parsed.append(None)

    valid_idx = [i for i, p in enumerate(parsed) if p]
    if not valid_idx:
        return [None] * len(requests)

    root, levels = build_merkle_tree([requests[i] for i in valid_idx])
    midpoint = server.get_time()
    responses: list[bytes | None] = [None] * len(requests)

    for merkle_idx, req_idx in enumerate(valid_idx):
        item = parsed[req_idx]
        if not item:
            continue
        ver, req = item
        path = get_merkle_path(levels, merkle_idx)
        responses[req_idx] = build_response(
            server,
            nonce=req.nonce,
            version=ver,
            midpoint=midpoint,
            root=root,
            path=path,
            index=merkle_idx,
        )

    return responses


class UDPHandler(asyncio.DatagramProtocol):
    def __init__(self, server: Server) -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        logger.debug("Received datagram from %s", addr)
        resp = handle_request(self.server, data)
        if resp and self.transport:
            self.transport.sendto(resp, addr)
            logger.debug("Sent response to %s", addr)
        else:
            logger.debug("No response sent to %s", addr)


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
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()
