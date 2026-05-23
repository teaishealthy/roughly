"""Tests for multi-request batching: Merkle trees, cross-group routing, BatchUDPHandler."""

from __future__ import annotations

import asyncio
import os

import pytest

import roughly.client
import roughly.server
from roughly.shared import DRAFT_VERSION_ZERO, ProtocolProfile

PRIVATE_KEY = roughly.server.generate_key()
PUBLIC_KEY_BYTES = roughly.server.public_key_bytes(PRIVATE_KEY)


def make_server() -> roughly.server.Server:
    return roughly.server.Server.create(private_key=PRIVATE_KEY.private_bytes_raw())


def make_request(versions: tuple[int, ...], *, nonce: bytes | None = None) -> bytes:
    """Build a padded 1024-byte request for the given version list."""
    return roughly.client.build_request(versions=versions, nonce=nonce).dump()


VERS_11 = (DRAFT_VERSION_ZERO | 10, DRAFT_VERSION_ZERO | 11)
VERS_15 = tuple(roughly.server.build_supported_versions(12, 15))


def test_empty_batch() -> None:
    server = make_server()
    assert roughly.server.handle_batch(server, ()) == []

def test_single_request_is_valid() -> None:
    server = make_server()
    raw = make_request(VERS_15)
    responses = roughly.server.handle_batch(server, (raw,))
    assert len(responses) == 1
    assert responses[0] is not None
    resp = roughly.client.VerifiableResponse.from_packet(raw=responses[0], request=raw)
    resp.verify(PUBLIC_KEY_BYTES)

def test_multiple_requests_same_group() -> None:
    """All draft-15 requests land in the same group: one SREP, each client verifies."""
    server = make_server()
    nonces = [os.urandom(32) for _ in range(4)]
    raws = [make_request(VERS_15, nonce=n) for n in nonces]

    responses = roughly.server.handle_batch(server, raws)
    assert len(responses) == 4

    roots: set[bytes] = set()
    indices: list[int] = []
    for raw, resp_bytes in zip(raws, responses, strict=True):
        assert resp_bytes is not None
        resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
        resp.verify(PUBLIC_KEY_BYTES)
        roots.add(resp.signed_response.root)
        indices.append(resp.index)

    assert len(roots) == 1, "All same-group requests must share a single Merkle root"
    assert len(set(indices)) == 4, "Each request must have a distinct Merkle index"

def test_cross_group_batching() -> None:
    """Requests from incompatible groups each get their own SREP and verify correctly."""
    server = make_server()
    raw_a = make_request(VERS_11)
    raw_b = make_request(VERS_15)

    responses = roughly.server.handle_batch(server, (raw_a, raw_b))
    assert len(responses) == 2
    assert responses[0] is not None
    assert responses[1] is not None

    resp_a = roughly.client.VerifiableResponse.from_packet(raw=responses[0], request=raw_a)
    resp_b = roughly.client.VerifiableResponse.from_packet(raw=responses[1], request=raw_b)
    resp_a.verify(PUBLIC_KEY_BYTES)
    resp_b.verify(PUBLIC_KEY_BYTES)

    assert resp_a.signed_response.root != resp_b.signed_response.root

def test_cross_group_root_isolation() -> None:
    """Each compatibility group's root only covers its own requests."""
    server = make_server()
    raws_a = [make_request(VERS_11, nonce=os.urandom(32)) for _ in range(3)]
    raws_b = [make_request(VERS_15, nonce=os.urandom(32)) for _ in range(2)]

    responses = roughly.server.handle_batch(server, raws_a + raws_b)
    assert len(responses) == 5

    roots_a: set[bytes] = set()
    roots_b: set[bytes] = set()

    for raw, resp_bytes in zip(raws_a, responses[:3], strict=True):
        assert resp_bytes is not None
        resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
        resp.verify(PUBLIC_KEY_BYTES)
        roots_a.add(resp.signed_response.root)

    for raw, resp_bytes in zip(raws_b, responses[3:], strict=True):
        assert resp_bytes is not None
        resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
        resp.verify(PUBLIC_KEY_BYTES)
        roots_b.add(resp.signed_response.root)

    assert len(roots_a) == 1
    assert len(roots_b) == 1
    assert roots_a.isdisjoint(roots_b), "Groups must not share a Merkle root"

def test_invalid_requests_yield_none() -> None:
    """Requests that are too small, wrong SRV, or missing TYPE are dropped silently."""
    server = make_server()
    valid = make_request(VERS_15)
    too_small = b"\x00" * 32
    wrong_srv = _make_request_with_wrong_srv(VERS_15)

    responses = roughly.server.handle_batch(server, (too_small, valid, wrong_srv))
    assert len(responses) == 3
    assert responses[0] is None
    assert responses[1] is not None
    assert responses[2] is None

def test_all_invalid_returns_none_list() -> None:
    server = make_server()
    responses = roughly.server.handle_batch(server, (b"\x00" * 32, b"\x01" * 64))
    assert responses == [None, None]

def test_merkle_path_verification() -> None:
    """PATH and INDX round-trip: every response in a batch verifies against ROOT."""
    server = make_server()
    n = 5
    raws = [make_request(VERS_15, nonce=os.urandom(32)) for _ in range(n)]
    responses = roughly.server.handle_batch(server, raws)

    for i, (raw, resp_bytes) in enumerate(zip(raws, responses, strict=True)):
        assert resp_bytes is not None, f"Request {i} got no response"
        resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
        resp.verify(PUBLIC_KEY_BYTES)


def test_single_request_empty_path() -> None:
    """A single request produces an empty PATH (it is the only leaf = the root)."""
    make_server()
    raw = make_request(VERS_15)
    req = roughly.server.Request.from_bytes(raw)
    profile = ProtocolProfile.from_version(DRAFT_VERSION_ZERO | 15)

    root, levels = roughly.server.build_merkle_tree(profile, (req,))
    path = roughly.server.get_merkle_path(levels, 0)

    assert path == [], "Single-request batch must have an empty Merkle path"
    expected = profile.hasher(b"\x00" + raw)
    assert root == expected

def test_two_requests_path_length_one() -> None:
    """Two requests produce a path of length 1 (one sibling hash)."""
    profile = ProtocolProfile.from_version(DRAFT_VERSION_ZERO | 15)
    raws = [make_request(VERS_15, nonce=os.urandom(32)) for _ in range(2)]
    reqs = [roughly.server.Request.from_bytes(r) for r in raws]

    _, levels = roughly.server.build_merkle_tree(profile, reqs)

    assert len(roughly.server.get_merkle_path(levels, 0)) == 1
    assert len(roughly.server.get_merkle_path(levels, 1)) == 1

def test_nonce_leaf_group() -> None:
    """Draft-11 group uses nonce as the leaf input."""
    raw = make_request(VERS_11, nonce=os.urandom(32))
    req = roughly.server.Request.from_bytes(raw)
    profile = ProtocolProfile.from_version(DRAFT_VERSION_ZERO | 11)
    assert not profile.leaf_from_request

    root, _ = roughly.server.build_merkle_tree(profile, (req,))
    expected = profile.hasher(b"\x00" + req.nonce)
    assert root == expected

def test_request_leaf_group() -> None:
    """Draft-15 group uses the full request packet as the leaf input."""
    raw = make_request(VERS_15, nonce=os.urandom(32))
    req = roughly.server.Request.from_bytes(raw)
    profile = ProtocolProfile.from_version(DRAFT_VERSION_ZERO | 15)
    assert profile.leaf_from_request

    root, _ = roughly.server.build_merkle_tree(profile, (req,))
    expected = profile.hasher(b"\x00" + raw)
    assert root == expected


@pytest.mark.asyncio
async def test_batch_udp_handler_single() -> None:
    """BatchUDPHandler responds correctly to a single UDP datagram."""
    server = make_server()
    raw = make_request(VERS_15)

    transport = await roughly.server._start_server(  # pyright: ignore[reportPrivateUsage]
        lambda: roughly.server.UDPHandler(server, window_ms=2.0),
        host="127.0.0.1",
        port=12002,
    )
    try:
        resp_bytes = await _udp_roundtrip("127.0.0.1", 12002, raw)
        assert resp_bytes is not None
        resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
        resp.verify(PUBLIC_KEY_BYTES)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_batch_udp_handler_concurrent() -> None:
    """Multiple datagrams sent within the window are batched and all receive responses."""
    server = make_server()
    n = 4
    raws = [make_request(VERS_15, nonce=os.urandom(32)) for _ in range(n)]

    transport = await roughly.server._start_server(  # pyright: ignore[reportPrivateUsage]
        lambda: roughly.server.UDPHandler(server, window_ms=20.0),
        host="127.0.0.1",
        port=12003,
    )
    try:
        loop = asyncio.get_running_loop()
        recv_transport, protocol = await loop.create_datagram_endpoint(
            roughly.client.QueueDatagramProtocol,
            remote_addr=("127.0.0.1", 12003),
        )
        try:
            for raw in raws:
                recv_transport.sendto(raw)

            responses: list[bytes] = []
            for _ in range(n):
                data = await asyncio.wait_for(protocol.recv(), timeout=2.0)
                responses.append(data)
        finally:
            recv_transport.close()

        roots: set[bytes] = set()
        for raw, resp_bytes in zip(raws, responses, strict=False):
            resp = roughly.client.VerifiableResponse.from_packet(raw=resp_bytes, request=raw)
            resp.verify(PUBLIC_KEY_BYTES)
            roots.add(resp.signed_response.root)

        assert len(roots) == 1, "Concurrently-sent requests should share a Merkle root"
    finally:
        transport.close()



async def _udp_roundtrip(host: str, port: int, data: bytes, *, timeout: float = 2.0) -> bytes:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        roughly.client.QueueDatagramProtocol,
        remote_addr=(host, port),
    )
    try:
        transport.sendto(data)
        return await asyncio.wait_for(protocol.recv(), timeout=timeout)
    finally:
        transport.close()


def _make_request_with_wrong_srv(versions: tuple[int, ...]) -> bytes:
    """Build a padded request that has an SRV tag pointing at a random key."""
    fake_key = os.urandom(32)
    return roughly.client.build_request(versions=versions, public_key=fake_key).dump()
