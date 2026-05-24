from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from roughly import client, server
from roughly.models import Message, Packet, SignedResponse, Tag, tags
from roughly.shared import DRAFT_VERSION_ZERO, RESPONSE_CONTEXT_STRING, ProtocolProfile

if TYPE_CHECKING:
    import pytest

PRIVATE_KEY = base64.b64decode("BuXi3Chpe7Nj3gCXavLUIoGbxngyrWVa3pYIHswbzbU=")
DRAFT_14 = DRAFT_VERSION_ZERO | 14
PROFILE_14 = ProtocolProfile.from_version(DRAFT_14)


def _make_server(**kwargs: object) -> server.Server:
    return server.Server.create(private_key=PRIVATE_KEY, **kwargs)  # pyright: ignore[reportArgumentType]


def _make_response_message(srv: server.Server, profile: ProtocolProfile = PROFILE_14) -> Message:
    raw = server.build_response(
        srv,
        nonce=b"\x00" * 32,
        profile=profile,
        midpoint=srv.get_time(),
        root=b"\x00" * 32,
        path=[],
        index=0,
    )
    return Packet.from_bytes(raw).message


def _verify_srep_signature(srv: server.Server, message: Message) -> bool:
    srep = next(t for t in message.tags if t.tag == tags.SREP)
    sig = next(t for t in message.tags if t.tag == tags.SIG)
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(server.public_key_bytes(srv.delegated_key))
    try:
        pubkey.verify(sig.value, RESPONSE_CONTEXT_STRING + srep.value)
    except InvalidSignature:
        return False
    return True


def test_grease_add_undefined_tag_adds_one_tag() -> None:
    srv = _make_server()
    msg = _make_response_message(srv)
    original_tag_ids = {t.tag for t in msg.tags}

    server.grease_add_undefined_tag(srv, PROFILE_14, msg)

    new_tag_ids = {t.tag for t in msg.tags}
    added = new_tag_ids - original_tag_ids
    assert len(added) == 1, "Expected exactly one new tag to be added"
    assert msg.tags == sorted(msg.tags, key=lambda t: t.tag)


def test_grease_remove_random_tag_removes_one_tag() -> None:
    srv = _make_server()
    msg = _make_response_message(srv)
    before = len(msg.tags)

    server.grease_remove_random_tag(srv, PROFILE_14, msg)

    assert len(msg.tags) == before - 1


def test_grease_change_time_invalidates_signature() -> None:
    # draft-16 §7 requires that incorrect times are paired with invalid signatures.
    srv = _make_server()
    msg = _make_response_message(srv)
    assert _verify_srep_signature(srv, msg), "baseline signature should be valid"

    server.grease_change_time(srv, PROFILE_14, msg)

    assert not _verify_srep_signature(srv, msg), (
        "time grease must produce an invalid signature"
    )


def test_grease_change_version_resigns_with_unsupported_version() -> None:
    srv = _make_server()
    msg = _make_response_message(srv)

    server.grease_change_version(srv, PROFILE_14, msg)

    srep_raw = next(t for t in msg.tags if t.tag == tags.SREP).value
    srep = SignedResponse.from_bytes(srep_raw, profile=PROFILE_14)
    assert srep.version not in srv.versions, "greased version must not be in supported set"
    assert _verify_srep_signature(srv, msg), (
        "version grease must keep SREP signature valid (re-signed)"
    )


def test_grease_message_applies_at_least_one_greaser(caplog: pytest.LogCaptureFixture) -> None:
    srv = _make_server()
    msg = _make_response_message(srv)
    before = Message(tags=[Tag(tag=t.tag, value=t.value) for t in msg.tags])

    caplog.set_level(logging.DEBUG, logger="roughly.server")
    greased = server.grease_message(srv, PROFILE_14, msg)

    assert any("Applied greaser" in r.message for r in caplog.records)
    assert greased.tags != before.tags


def test_grease_message_falls_back_when_greaser_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    srv = _make_server()
    msg = _make_response_message(srv)

    def broken(srv: server.Server, profile: ProtocolProfile, message: Message) -> Message:
        message.tags.append(Tag(tag=0xDEADBEEF, value=b"\x00\x00\x00\x00"))
        raise RuntimeError("intentional grease failure")

    with patch.object(server, "GREASERS", [broken]):
        caplog.set_level(logging.DEBUG, logger="roughly.server")
        greased = server.grease_message(srv, PROFILE_14, msg)

    assert 0xDEADBEEF not in {t.tag for t in greased.tags}, (
        "broken greaser's mutation must be reverted"
    )
    assert any("failed, reverting" in r.message for r in caplog.records)
    assert any(
        r.levelno == logging.WARNING and "No greasers managed to apply" in r.message
        for r in caplog.records
    ), "expected WARN when no greaser succeeded"


def test_grease_message_continues_after_one_greaser_fails() -> None:
    srv = _make_server()
    msg = _make_response_message(srv)

    calls: list[str] = []

    def broken(srv: server.Server, profile: ProtocolProfile, message: Message) -> Message:
        calls.append("broken")
        raise RuntimeError("boom")

    def ok(srv: server.Server, profile: ProtocolProfile, message: Message) -> Message:
        calls.append("ok")
        message.tags.append(Tag(tag=0xCAFEBABE, value=b"\x00\x00\x00\x00"))
        message.tags.sort(key=lambda t: t.tag)
        return message

    with (
        patch.object(server, "GREASERS", [broken, ok]),
        patch.object(server.random, "randint", return_value=2),
        patch.object(server.random, "sample", side_effect=lambda pop, k: list(pop)),
    ):
        greased = server.grease_message(srv, PROFILE_14, msg)

    assert calls == ["broken", "ok"]
    assert 0xCAFEBABE in {t.tag for t in greased.tags}


def test_handle_batch_uses_greased_message() -> None:
    # grease_probability=1.0 forces every response to be greased.
    srv = _make_server(grease=True, grease_probability=1.0)
    req_packet = client.build_request(
        public_key=server.public_key_bytes(srv.long_term_key),
        versions=[DRAFT_14],
    )

    sentinel_tag = 0xFEEDFACE

    def sentinel_greaser(srv: server.Server, profile: ProtocolProfile, message: Message) -> Message:
        message.tags.append(Tag(tag=sentinel_tag, value=b"\x00\x00\x00\x00"))
        message.tags.sort(key=lambda t: t.tag)
        return message

    with (
        patch.object(server, "GREASERS", [sentinel_greaser]),
        patch.object(server.random, "randint", return_value=1),
        patch.object(server.random, "sample", side_effect=lambda pop, k: list(pop)),
        # Force the unconditional grease branch (random.random() < 1.0 is always True,
        # but patch to be explicit).
        patch.object(server.random, "random", return_value=0.0),
        # Defeat the response-size ceiling that drops oversized responses.
        patch.object(server, "PACKET_SIZE", 1),
    ):
        response, *_ = server.handle_batch(srv, (req_packet.dump(),))

    assert response is not None
    out = Packet.from_bytes(response)
    assert sentinel_tag in {t.tag for t in out.message.tags}


def test_grease_disabled_by_default_in_handle_batch() -> None:
    srv = _make_server()  # grease defaults to False
    req_packet = client.build_request(
        public_key=server.public_key_bytes(srv.long_term_key),
        versions=[DRAFT_14],
    )

    def explode(srv: server.Server, profile: ProtocolProfile, message: Message) -> Message:
        raise AssertionError("grease_message should not be called when grease=False")

    with patch.object(server, "grease_message", explode):
        response, *_ = server.handle_batch(srv, (req_packet.dump(),))

    assert response is not None
