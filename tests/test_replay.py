import base64
import itertools
import json
import operator
import pathlib
from typing import TypedDict

import pytest

import roughly
import roughly.server

PRIVATE_KEY = base64.b64decode("BuXi3Chpe7Nj3gCXavLUIoGbxngyrWVa3pYIHswbzbU=")
PUBLIC_KEY = base64.b64decode("Ixu7gqjJ9TU6IxsO8wxZxAFT5te6FcZZQq5vXFl35JE=")

CLIENT = 1
SERVER = 0


class PartialPacketEntry(TypedDict):
    request: bytes
    response: bytes


class PacketEntry(PartialPacketEntry):
    role: int  # 1 for client, 0 for server
    request: bytes
    response: bytes
    other: str  # other party's name


def decode_packet(packet: PacketEntry) -> PartialPacketEntry:
    request = base64.b64decode(packet["request"])
    response = base64.b64decode(packet["response"])
    return {
        "request": request,
        "response": response,
    }


def load_packets() -> list[PacketEntry]:
    path = pathlib.Path(__file__).parent / "packets.json"
    with path.open("r") as f:
        return [{**p, **decode_packet(p)} for p in sorted(json.load(f), key=GETTER)]  # pyright: ignore[reportReturnType]


GETTER = operator.itemgetter("role")
PACKETS = {role: list(items) for role, items in itertools.groupby(load_packets(), key=GETTER)}


@pytest.mark.parametrize("packet", PACKETS[CLIENT], ids=lambda p: f"client-{p['other']}")
def test_replay_client(packet: PacketEntry) -> None:
    resp = roughly.Response.from_packet(raw=packet["response"], request=packet["request"])
    resp.verify(PUBLIC_KEY)


@pytest.mark.parametrize("packet", PACKETS[SERVER], ids=lambda p: f"server-{p['other']}")
def test_replay_server(packet: PacketEntry) -> None:
    server = roughly.server.Server.create(private_key=PRIVATE_KEY)

    req = roughly.server.Request.from_bytes(packet["request"])
    version = roughly.server.select_version(req.versions, roughly.server.CLIENT_VERSIONS_SUPPORTED)
    assert version is not None, "No compatible version found"
    req.validate(version)

    responses = roughly.server.handle_batch(server, (req.raw,))

    assert len(responses) == 1, "Expected exactly one response"
    assert responses[0] is not None, "Response is None"

    # the server supports draft-10 to draft-15 (+ Google Roughtime)
    # and the client supports draft-7 to draft-15
    # so we should be able to parse all responses except Google Roughtime
    # this test is slightly out of scope but it's a good sanity check
    if version != roughly.server.GOOGLE_ROUGHTIME_SENTINEL:
        resp = roughly.Response.from_packet(raw=responses[0], request=packet["request"])
        resp.verify(PUBLIC_KEY)
