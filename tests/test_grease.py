from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

import roughly
from roughly import server, tags

if TYPE_CHECKING:
    import pytest

PRIVATE_KEY = base64.b64decode("BuXi3Chpe7Nj3gCXavLUIoGbxngyrWVa3pYIHswbzbU=")
DRAFT_14 = roughly.DRAFT_VERSION_ZERO | 14


def _make_server(**kwargs: object) -> server.Server:
    return server.Server.create(private_key=PRIVATE_KEY, **kwargs)  # pyright: ignore[reportArgumentType]


def _make_response_packet(srv: server.Server, version: int = DRAFT_14) -> roughly.Packet:
    return server.build_response(
        srv,
        nonce=b"\x00" * 32,
        version=version,
        midpoint=srv.get_time(),
        root=b"\x00" * 32,
        path=[],
        index=0,
    )


def _verify_srep_signature(srv: server.Server, message: roughly.Message) -> bool:
    srep = next(t for t in message.tags if t.tag == tags.SREP)
    sig = next(t for t in message.tags if t.tag == tags.SIG)
    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(server.public_key_bytes(srv.delegated_key))
    try:
        pubkey.verify(sig.value, roughly.RESPONSE_CONTEXT_STRING + srep.value)
    except InvalidSignature:
        return False
    return True


def test_grease_add_undefined_tag_adds_one_tag() -> None:
    srv = _make_server()
    packet = _make_response_packet(srv)
    original_tag_ids = {t.tag for t in packet.message.tags}

    server.grease_add_undefined_tag(srv, packet.message)

    new_tag_ids = {t.tag for t in packet.message.tags}
    added = new_tag_ids - original_tag_ids
    assert len(added) == 1, "Expected exactly one new tag to be added"
    # Tags remain sorted
    assert packet.message.tags == sorted(packet.message.tags, key=lambda t: t.tag)


def test_grease_remove_random_tag_removes_one_tag() -> None:
    srv = _make_server()
    packet = _make_response_packet(srv)
    before = len(packet.message.tags)

    server.grease_remove_random_tag(srv, packet.message)

    assert len(packet.message.tags) == before - 1


def test_grease_change_time_invalidates_signature() -> None:
    # draft-16 §7 requires that incorrect times are paired with invalid signatures.
    srv = _make_server()
    packet = _make_response_packet(srv)
    assert _verify_srep_signature(srv, packet.message), "baseline signature should be valid"

    server.grease_change_time(srv, packet.message)

    assert not _verify_srep_signature(srv, packet.message), (
        "time grease must produce an invalid signature"
    )


def test_grease_change_version_resigns_with_unsupported_version() -> None:
    srv = _make_server()
    packet = _make_response_packet(srv)

    server.grease_change_version(srv, packet.message)

    srep_raw = next(t for t in packet.message.tags if t.tag == tags.SREP).value
    srep = roughly.SignedResponse.from_bytes(srep_raw)
    assert srep.version not in srv.versions, "greased version must not be in supported set"
    assert _verify_srep_signature(srv, packet.message), (
        "version grease must keep SREP signature valid (re-signed)"
    )


def test_grease_message_applies_at_least_one_greaser(caplog: pytest.LogCaptureFixture) -> None:
    srv = _make_server()
    packet = _make_response_packet(srv)
    before = roughly.Message(
        tags=[roughly.Tag(tag=t.tag, value=t.value) for t in packet.message.tags]
    )

    caplog.set_level(logging.DEBUG, logger="roughly.server")
    greased = server.grease_message(srv, packet.message)

    assert any("Applied greaser" in r.message for r in caplog.records)
    # Something must have changed
    assert greased.tags != before.tags


def test_grease_message_falls_back_when_greaser_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    srv = _make_server()
    packet = _make_response_packet(srv)

    def broken(srv: server.Server, message: roughly.Message) -> roughly.Message:
        # Mutate before raising — the snapshot revert must undo this.
        message.tags.append(roughly.Tag(tag=0xDEADBEEF, value=b"\x00\x00\x00\x00"))
        raise RuntimeError("intentional grease failure")

    with patch.object(server, "GREASERS", [broken]):
        caplog.set_level(logging.DEBUG, logger="roughly.server")
        greased = server.grease_message(srv, packet.message)

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
    packet = _make_response_packet(srv)

    calls: list[str] = []

    def broken(srv: server.Server, message: roughly.Message) -> roughly.Message:
        calls.append("broken")
        raise RuntimeError("boom")

    def ok(srv: server.Server, message: roughly.Message) -> roughly.Message:
        calls.append("ok")
        message.tags.append(roughly.Tag(tag=0xCAFEBABE, value=b"\x00\x00\x00\x00"))
        message.tags.sort(key=lambda t: t.tag)
        return message

    with (
        patch.object(server, "GREASERS", [broken, ok]),
        # Force both greasers to be picked.
        patch.object(server.random, "randint", return_value=2),
        patch.object(server.random, "sample", side_effect=lambda pop, k: list(pop)),
    ):
        greased = server.grease_message(srv, packet.message)

    assert calls == ["broken", "ok"]
    assert 0xCAFEBABE in {t.tag for t in greased.tags}


def test_handle_batch_uses_greased_message() -> None:
    # When grease_probability=1.0 every response is greased; ensure the server
    # actually applies the mutation to the wire output (handle_batch uses the
    # return value, not in-place semantics).
    srv = _make_server(grease=True, grease_probability=1.0)
    req_packet = roughly.build_request(
        public_key=server.public_key_bytes(srv.long_term_key),
        versions=[DRAFT_14],
    )

    sentinel_tag = 0xFEEDFACE

    def sentinel_greaser(srv: server.Server, message: roughly.Message) -> roughly.Message:
        message.tags.append(roughly.Tag(tag=sentinel_tag, value=b"\x00\x00\x00\x00"))
        message.tags.sort(key=lambda t: t.tag)
        return message

    with (
        patch.object(server, "GREASERS", [sentinel_greaser]),
        patch.object(server.random, "randint", return_value=1),
        patch.object(server.random, "sample", side_effect=lambda pop, k: list(pop)),
        patch.object(server, "PACKET_SIZE", 1),
    ):
        response, *_ = server.handle_batch(srv, (req_packet.dump(),))

    assert response is not None
    out = roughly.Packet.from_bytes(response)
    assert sentinel_tag in {t.tag for t in out.message.tags}


def test_grease_disabled_by_default_in_handle_batch() -> None:
    srv = _make_server()  # grease defaults to False
    req_packet = roughly.build_request(
        public_key=server.public_key_bytes(srv.long_term_key),
        versions=[DRAFT_14],
    )

    def explode(srv: server.Server, message: roughly.Message) -> roughly.Message:
        raise AssertionError("grease_message should not be called when grease=False")

    with patch.object(server, "grease_message", explode):
        responses = server.handle_batch(srv, (req_packet.dump(),))

    assert responses[0] is not None
