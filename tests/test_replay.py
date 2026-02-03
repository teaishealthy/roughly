import base64
import itertools
import json
import operator
import pathlib
from collections.abc import Iterable
from typing import TypedDict

import pytest

import roughly.client
import roughly.models
import roughly.server
import roughly.shared
import roughly.tags

PRIVATE_KEY = base64.b64decode("BuXi3Chpe7Nj3gCXavLUIoGbxngyrWVa3pYIHswbzbU=")
PUBLIC_KEY = base64.b64decode("Ixu7gqjJ9TU6IxsO8wxZxAFT5te6FcZZQq5vXFl35JE=")

# this is the public key from sth2.roughtime.netnod.se
DRAFT_7_PUB_KEY = base64.b64decode("T/xxX4ERUBAOpt64Z8phWamKsASZxJ0VWuiPm3GS/8g=")

CLIENT = 1
SERVER = 0

NESTED_TAGS: list[tuple[tuple[int, ...], int]] = [
    ((), roughly.tags.SREP),
    ((), roughly.tags.CERT),
    ((roughly.tags.CERT,), roughly.tags.DELE),
]


class PartialPacketEntry(TypedDict):
    request: bytes
    response: bytes


class PacketEntry(PartialPacketEntry):
    role: int  # 1 for client, 0 for server
    request: bytes
    response: bytes
    other: str  # other party's name


def get_tags(message: roughly.models.Message) -> set[int]:
    return {tag.tag for tag in message.tags}


def get_nested_message(
    message: roughly.models.Message, path: Iterable[int]
) -> roughly.models.Message:
    for tag_id in path:
        for tag in message.tags:
            if tag.tag == tag_id:
                message = roughly.models.Message.from_bytes(tag.value)
                break
    return message


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
    resp = roughly.client.VerifiableResponse.from_packet(
        raw=packet["response"], request=packet["request"]
    )
    if resp.version == roughly.shared.DRAFT_VERSION_ZERO | 7:
        resp.verify(DRAFT_7_PUB_KEY)
    else:
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
        resp = roughly.client.VerifiableResponse.from_packet(
            raw=responses[0], request=packet["request"]
        )
        resp.verify(PUBLIC_KEY)

    original_packet = roughly.models.Packet.from_bytes(packet["response"])
    response_packet = roughly.models.Packet.from_bytes(responses[0])

    assert get_tags(original_packet.message) <= get_tags(response_packet.message), (
        "Missing top-level tags"
    )

    for path, tag_id in NESTED_TAGS:
        original_parent = get_nested_message(original_packet.message, path)
        generated_parent = get_nested_message(response_packet.message, path)

        original_nested = get_nested_message(original_parent, [tag_id])
        generated_nested = get_nested_message(generated_parent, [tag_id])

        tag_name = tag_id.to_bytes(4, "little").decode("ascii", errors="replace")

        assert get_tags(original_nested) <= get_tags(generated_nested), f"Missing {tag_name} tags"
