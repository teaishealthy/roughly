"""Malformed input must raise RoughtimeError, never a bare struct.error."""

from __future__ import annotations

import os
import random
import struct

import pytest

from roughly import client, server, tags
from roughly.errors import RoughtimeError
from roughly.models import Message, Packet, Tag
from roughly.shared import DRAFT_VERSION_ZERO, PACKET_SIZE, ROUGHTIM

DRAFT_15 = DRAFT_VERSION_ZERO | 15
VERS_15 = tuple(server.build_supported_versions(12, 15))

PRIVATE_KEY = server.generate_key()


def make_server() -> server.Server:
    return server.Server.create(private_key=PRIVATE_KEY.private_bytes_raw())


def make_request() -> bytes:
    return client.build_request(versions=VERS_15).dump()


def frame(message: bytes) -> bytes:
    """Frame a message into a full-size packet the server will not drop as too small.

    The message is zero-padded and the declared length kept consistent, so the
    packet reaches the message parser instead of failing the framing checks.
    """
    body = message.ljust(PACKET_SIZE - Packet.header_size, b"\x00")
    return struct.pack("<Q", ROUGHTIM) + struct.pack("<I", len(body)) + body


MALFORMED_MESSAGES = {
    "empty": b"",
    "partial_tag_count": b"\x02\x00\x00",
    "count_only": struct.pack("<I", 2),
    "zero_pairs": struct.pack("<I", 0),
    # Declares more pairs than the buffer could ever hold.
    "huge_pair_count": struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 512,
    "pair_count_overruns_buffer": struct.pack("<I", 64) + b"\x00" * 32,
    # Two pairs, first value offset points far past the value section.
    "offset_past_end": (
        struct.pack("<I", 2)
        + struct.pack("<I", 0x1000)
        + struct.pack("<I", 1)
        + struct.pack("<I", 2)
        + b"\x00" * 8
    ),
    "unaligned_offset": (
        struct.pack("<I", 2)
        + struct.pack("<I", 3)
        + struct.pack("<I", 1)
        + struct.pack("<I", 2)
        + b"\x00" * 8
    ),
    # Single pair whose value section is not a whole number of words.
    "unaligned_values": struct.pack("<I", 1) + struct.pack("<I", tags.TYPE) + b"\x00" * 3,
}


@pytest.mark.parametrize("data", MALFORMED_MESSAGES.values(), ids=list(MALFORMED_MESSAGES))
def test_malformed_message_raises_roughtime_error(data: bytes) -> None:
    with pytest.raises(RoughtimeError):
        Message.from_bytes(data)


@pytest.mark.parametrize("length", [0, 1, 4, 11])
def test_short_packet_raises_roughtime_error(length: int) -> None:
    """Below the 12-byte framing header there is nothing valid to parse."""
    with pytest.raises(RoughtimeError):
        Packet.from_bytes(b"\x00" * length)


@pytest.mark.parametrize("data", MALFORMED_MESSAGES.values(), ids=list(MALFORMED_MESSAGES))
def test_server_drops_malformed_message_without_raising(data: bytes) -> None:
    srv = make_server()
    assert server.handle_batch(srv, (frame(data),)) == [None]


@pytest.mark.parametrize(
    ("tag_id", "value"),
    [
        (tags.TYPE, b"\x00" * 8),
        (tags.TYPE, b""),
        (tags.VER, b""),
    ],
)
def test_server_drops_request_with_wrong_sized_scalar(tag_id: int, value: bytes) -> None:
    """A wrong-length TYPE/VER value must not reach struct.unpack unchecked."""
    srv = make_server()
    msg = Message(
        tags=[
            Tag(tag=tags.VER, value=struct.pack("<I", DRAFT_15)),
            Tag(tag=tags.NONC, value=os.urandom(32)),
            Tag(tag=tags.TYPE, value=struct.pack("<I", tags.TYPE_REQUEST)),
        ]
    )
    for tag in msg.tags:
        if tag.tag == tag_id:
            tag.value = value
    msg.prepare()
    assert server.handle_batch(srv, (Packet(message=msg).dump(),)) == [None]


def test_response_with_certificate_missing_dele_raises_roughtime_error() -> None:
    """A CERT without DELE is malformed input, not a broken internal invariant."""
    srv = make_server()
    request = make_request()
    raw = server.handle_batch(srv, (request,))[0]
    assert raw is not None

    packet = Packet.from_bytes(raw)
    for tag in packet.message.tags:
        if tag.tag == tags.CERT:
            tag.value = Message(tags=[Tag(tag=tags.SIG, value=b"\x00" * 64)]).to_bytes()

    with pytest.raises(RoughtimeError):
        client.VerifiableResponse.from_packet(raw=packet.dump(), request=request)


def test_fuzzed_responses_never_escape_as_non_roughtime_errors() -> None:
    """Bit-flipped responses must surface as RoughtimeError for the client too."""
    srv = make_server()
    request = make_request()
    base = server.handle_batch(srv, (request,))[0]
    assert base is not None
    public_key = server.public_key_bytes(PRIVATE_KEY)
    rng = random.Random(7)  # noqa: S311

    for _ in range(1000):
        mutated = bytearray(base)
        for _ in range(rng.randint(1, 10)):
            mutated[rng.randrange(len(mutated))] = rng.getrandbits(8)
        try:
            response = client.VerifiableResponse.from_packet(raw=bytes(mutated), request=request)
            response.verify(public_key)
        except RoughtimeError:
            continue


def test_fuzzed_requests_never_escape_handle_batch() -> None:
    """Random and bit-flipped packets are dropped, never propagated as exceptions."""
    srv = make_server()
    base = make_request()
    rng = random.Random(1234)  # noqa: S311

    for i in range(2000):
        if i % 2 == 0:
            data = bytes(rng.getrandbits(8) for _ in range(PACKET_SIZE))
        else:
            mutated = bytearray(base)
            for _ in range(rng.randint(1, 8)):
                mutated[12 + rng.randrange(64)] = rng.getrandbits(8)
            data = bytes(mutated)

        assert server.handle_batch(srv, (data,)) is not None
