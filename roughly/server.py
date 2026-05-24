from __future__ import annotations

import asyncio
import copy
import logging
import os
import string
import struct
import time
from collections import defaultdict
from contextlib import contextmanager
from random import SystemRandom
from typing import TYPE_CHECKING, NamedTuple

from cryptography.hazmat.primitives.asymmetric import ed25519

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Sequence

from roughly.errors import RoughtimeError
from roughly.models import (
    Certificate,
    Delegation,
    Message,
    Packet,
    PacketError,
    Response,
    SignedResponse,
    Tag,
    tags,
)
from roughly.shared import (
    DELEGATION_CONTEXT_STRING,
    DELEGATION_CONTEXT_STRING_OLD,
    DRAFT_VERSION_ZERO,
    GOOGLE_ROUGHTIME_SENTINEL,
    PACKET_SIZE,
    RESPONSE_CONTEXT_STRING,
    ProfileKey,
    ProtocolProfile,
    build_supported_versions,
    format_versions,
    partial_sha512,
    pop_by_tag,
    pop_by_tag_optional,
)

random = SystemRandom()

logger = logging.getLogger(__name__)


DEFAULT_RADIUS = int(os.environ.get("ROUGHLY_DEFAULT_RADIUS", "3"))
CLIENT_VERSIONS_SUPPORTED = build_supported_versions(10, 15)

CERT_VALIDITY = 60 * 60  # 1 hour

GREASE_PROBABILITY = 0.001


def grease_add_undefined_tag(
    server: Server,  # noqa: ARG001
    profile: ProtocolProfile,  # noqa: ARG001
    message: Message,
) -> Message:
    tag_name = int.from_bytes(random.choices(string.ascii_uppercase.encode("ascii"), k=4))
    tag_value = os.urandom(random.randint(1, 16) * 4)

    message.tags.append(Tag(tag=tag_name, value=tag_value))
    message.tags.sort(key=lambda t: t.tag)
    return message


def grease_remove_random_tag(
    server: Server,  # noqa: ARG001
    profile: ProtocolProfile,  # noqa: ARG001
    message: Message,
) -> Message:
    if message.tags:
        message.tags.remove(random.choice(message.tags))
    return message


def grease_change_version(server: Server, profile: ProtocolProfile, message: Message) -> Message:
    srep_raw = pop_by_tag(message.tags, tags.SREP)
    srep = SignedResponse.from_bytes(srep_raw.value, profile=profile)

    forbidden = set(server.versions) | {srep.version}
    while True:
        candidate = DRAFT_VERSION_ZERO | random.randint(20, 0xFFFF)
        if candidate not in forbidden:
            break
    srep.version = candidate

    new_srep_raw = srep.to_bytes()
    new_sig = server.delegated_key.sign(RESPONSE_CONTEXT_STRING + new_srep_raw)

    sig_tag = pop_by_tag(message.tags, tags.SIG)
    sig_tag.value = new_sig

    message.tags.append(Tag(tag=tags.SREP, value=new_srep_raw))
    message.tags.append(sig_tag)
    message.tags.sort(key=lambda t: t.tag)
    return message


def grease_change_time(
    server: Server,  # noqa: ARG001
    profile: ProtocolProfile,
    message: Message,
) -> Message:
    # draft-16 §7: incorrect times must be paired with an invalid signature.
    srep_raw = pop_by_tag(message.tags, tags.SREP)
    srep = SignedResponse.from_bytes(srep_raw.value, profile=profile)

    srep.midpoint = random.randint(0, 0x100000000)
    new_srep_raw = srep.to_bytes()
    message.tags.append(Tag(tag=tags.SREP, value=new_srep_raw))
    message.tags.sort(key=lambda t: t.tag)
    return message


GREASERS: list[Callable[[Server, ProtocolProfile, Message], Message]] = [
    grease_add_undefined_tag,
    grease_remove_random_tag,
    grease_change_time,
    grease_change_version,
]


def grease_message(server: Server, profile: ProtocolProfile, message: Message) -> Message:
    count = random.randint(1, len(GREASERS))
    chosen = random.sample(GREASERS, count)

    applied = 0
    for greaser in chosen:
        snapshot = copy.deepcopy(message)
        try:
            greaser(server, profile, message)
        except Exception:  # noqa: BLE001
            logger.debug("Greaser %s failed, reverting", greaser.__name__, exc_info=True)
            message = snapshot
            continue
        logger.debug("Applied greaser: %s", greaser.__name__)
        applied += 1

    if applied == 0:
        logger.warning("No greasers managed to apply.")

    return message


class CertificateStore(NamedTuple):
    certs: dict[bytes, Certificate]
    """Keyed on delegation_context bytes."""
    google_cert: Certificate
    expiry: int


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
    cert_times_in_microseconds: bool = False,
) -> Certificate:
    """Create and sign a delegation certificate."""
    if cert_times_in_microseconds:
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

        def make_cert(string: bytes, *, cert_times_in_microseconds: bool = False) -> Certificate:
            return create_certificate(
                long_term,
                delegated,
                now,
                expiry,
                string,
                cert_times_in_microseconds=cert_times_in_microseconds,
            )

        certificates = CertificateStore(
            certs={
                DELEGATION_CONTEXT_STRING: make_cert(DELEGATION_CONTEXT_STRING),
                DELEGATION_CONTEXT_STRING_OLD: make_cert(DELEGATION_CONTEXT_STRING_OLD),
            },
            google_cert=make_cert(DELEGATION_CONTEXT_STRING_OLD, cert_times_in_microseconds=True),
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

    def validate(self, profile: ProtocolProfile) -> None:
        if profile.type_tag_required:
            if self.type is None:
                raise PacketError(f"Missing TYPE for version {profile.version}")
            if self.type != tags.TYPE_REQUEST:
                raise PacketError(f"Invalid TYPE {self.type}, expected {tags.TYPE_REQUEST}")

        if len(self.nonce) != profile.nonce_size:
            raise PacketError(f"Invalid NONC size {len(self.nonce)}, expected {profile.nonce_size}")


def select_version(client: Sequence[int], server: Sequence[int]) -> int | None:
    if GOOGLE_ROUGHTIME_SENTINEL in client:
        return GOOGLE_ROUGHTIME_SENTINEL
    common = set(client) & set(server)
    return max(common) if common else None


def build_merkle_tree(
    profile: ProtocolProfile, requests: Sequence[Request]
) -> tuple[bytes, list[list[bytes]]]:
    leaves: list[bytes] = []

    for r in requests:
        raw = r.raw if profile.leaf_from_request else r.nonce
        leaves.append(profile.hasher(b"\x00" + raw))

    size = 1
    while size < len(leaves):
        size *= 2
    while len(leaves) < size:
        leaves.append(leaves[-1])

    levels: list[list[bytes]] = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = [
            profile.hasher(b"\x01" + current[i] + current[i + 1]) for i in range(0, len(current), 2)
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
    profile: ProtocolProfile,
    midpoint: int,
    root: bytes,
    path: list[bytes],
    index: int,
) -> bytes:
    midpoint_wire = midpoint * 1_000_000 if profile.midpoint_in_microseconds else midpoint
    radius_wire = server.radius * 1_000_000 if profile.midpoint_in_microseconds else server.radius

    srep = SignedResponse(
        radius=radius_wire,
        midpoint=midpoint_wire,
        root=root,
        version=profile.version,
        versions=server.versions,
    )

    cert = pick_cert(certificates=server.certificates, profile=profile)
    resp = make_response(server, nonce, profile, path, index, srep, cert)
    return Packet(message=resp).dump(profile=profile)


def pick_cert(*, certificates: CertificateStore, profile: ProtocolProfile) -> Certificate:
    if not profile.packet_framing:  # Google
        return certificates.google_cert
    return certificates.certs[profile.delegation_context]


def make_response(  # noqa: PLR0913
    server: Server,
    nonce: bytes,
    profile: ProtocolProfile,
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
        type=tags.TYPE_RESPONSE if profile.packet_framing else None,
        path=path,
        signed_response=srep,
        certificate=cert,
        index=index,
    )

    return response.to_message(profile=profile)



@contextmanager
def _rethrow(old: type[BaseException], new: type[BaseException]) -> Generator[None, None, None]:
    try:
        yield
    except old as e:
        raise new from e


def handle_batch(server: Server, requests: Sequence[bytes]) -> list[bytes | None]:
    if not requests:
        return []

    expected = srv_hash(server.long_term_key)
    parsed: list[tuple[int, Request, ProtocolProfile] | None] = []

    for i, data in enumerate(requests):
        try:
            if len(data) < PACKET_SIZE:
                logger.debug("Dropped request that is too small")
                parsed.append(None)
                continue

            with _rethrow(RoughtimeError, PacketError):
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

            profile = ProtocolProfile.from_version(ver)

            with _rethrow(RoughtimeError, PacketError):
                req.validate(profile)

            if req.srv is not None and req.srv != expected:
                parsed.append(None)
                logger.debug("Dropped request with invalid SRV")
                continue

            parsed.append((i, req, profile))
        except PacketError:
            logger.exception("Dropped invalid request")
            parsed.append(None)

    valid = [
        (req_id, req, profile)
        for entry in parsed
        if entry is not None
        for req_id, req, profile in (entry,)
    ]
    if not valid:
        return [None] * len(requests)

    # Group by compatibility key: (hasher, leaf_from_request)
    groups: defaultdict[ProfileKey, list[tuple[int, Request, ProtocolProfile]]] = defaultdict(list)
    for req_id, req, profile in valid:
        groups[profile.key].append((req_id, req, profile))

    midpoint = server.get_time()
    responses: list[bytes | None] = [None] * len(requests)

    for group in groups.values():
        _process_group(server, group, midpoint, responses)

    return responses


def _process_group(
    server: Server,
    group: list[tuple[int, Request, ProtocolProfile]],
    midpoint: int,
    output: list[bytes | None],
) -> None:
    ((_, _, profile), *_) = group

    requests_only = [req for _, req, _ in group]
    root, levels = build_merkle_tree(profile, requests_only)

    midpoint_wire = midpoint * 1_000_000 if profile.midpoint_in_microseconds else midpoint
    radius_wire = server.radius * 1_000_000 if profile.midpoint_in_microseconds else server.radius

    srep = SignedResponse(
        radius=radius_wire,
        midpoint=midpoint_wire,
        root=root,
        version=profile.version,
        versions=server.versions,
    )
    srep_raw = srep.to_bytes()
    sig = server.delegated_key.sign(RESPONSE_CONTEXT_STRING + srep_raw)
    cert = pick_cert(certificates=server.certificates, profile=profile)

    for merkle_idx, (req_id, req, req_profile) in enumerate(group):
        path = get_merkle_path(levels, merkle_idx)
        response = Response(
            signature=sig,
            nonce=req.nonce,
            type=tags.TYPE_RESPONSE if req_profile.packet_framing else None,
            path=path,
            signed_response=srep,
            certificate=cert,
            index=merkle_idx,
        )
        message = response.to_message(profile=req_profile)

        if server.grease and random.random() < server.grease_probability:
            logger.debug("Greasing response for request %d", req_id)
            message = grease_message(server, req_profile, message)

        raw = Packet(message=message).dump(profile=req_profile)
        if len(raw) > len(req.raw):
            logger.debug(
                "Dropping response larger than request (response: %d, request: %d)",
                len(raw),
                len(req.raw),
            )
            continue
        output[req_id] = raw


class UDPHandler(asyncio.DatagramProtocol):
    def __init__(self, server: Server, *, window_ms: float = 5.0) -> None:
        self.server = server
        self.window_ms = window_ms
        self.transport: asyncio.DatagramTransport | None = None
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        self._task = asyncio.get_event_loop().create_task(_batch_processor(self))

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.queue.put_nowait((data, addr))

    def connection_lost(self, exc: Exception | None) -> None:  # noqa: ARG002
        if self._task:
            self._task.cancel()


async def _batch_processor(handler: UDPHandler) -> None:
    while True:
        batch = [await handler.queue.get()]
        deadline = asyncio.get_event_loop().time() + handler.window_ms / 1000
        while (remaining := deadline - asyncio.get_event_loop().time()) > 0:
            try:
                batch.append(await asyncio.wait_for(handler.queue.get(), timeout=remaining))
            except TimeoutError:
                break

        if handler.server.certificates.expiry < handler.server.get_time():
            logger.info("Server key expired, refreshing")
            handler.server = handler.server.refresh()

        raw_list = [data for data, _ in batch]
        addrs = [addr for _, addr in batch]
        responses = handle_batch(handler.server, raw_list)

        if handler.transport:
            for resp, addr in zip(responses, addrs, strict=True):
                if resp:
                    handler.transport.sendto(resp, addr)


async def serve(
    server: Server,
    host: str = "0.0.0.0",  # noqa: S104
    port: int = 2002,
) -> None:
    """Start a Roughtime server.

    Args:
        server (Server): The server to run.
        host (str, optional): The host to bind to. Defaults to "0.0.0.0"
        port (int, optional): The port to listen on. Defaults to 2002.
    """
    transport = await _start_server(lambda: UDPHandler(server), host, port)

    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


async def _start_server(
    factory: Callable[[], asyncio.DatagramProtocol],
    host: str,
    port: int,
) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(factory, local_addr=(host, port))
    logger.info("Listening on %s:%d", host, port)
    return transport
