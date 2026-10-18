from dataclasses import replace

import pytest

from roughly import client, server, tags
from roughly.errors import PacketError, VerificationError
from roughly.models import Packet
from roughly.shared import (
    DRAFT_VERSION_ZERO,
    GOOGLE_ROUGHTIME_SENTINEL,
    ProtocolProfile,
    get_by_tag,
    partial_sha512,
)


def test_rfc_profile_preserves_wire_version_and_uses_rfc_contexts() -> None:
    profile = ProtocolProfile.from_version(1)
    assert profile.version == 1
    assert profile.response_context == b"Roughtime v1 response signature\x00"
    assert profile.delegation_context == b"Roughtime v1 delegation signature\x00"

    # The remaining protocol parameters match the latest supported draft profile.
    draft = ProtocolProfile.from_version(DRAFT_VERSION_ZERO | 15)
    assert profile == replace(
        draft,
        version=1,
        response_context=profile.response_context,
        delegation_context=profile.delegation_context,
    )
    assert profile.hasher is partial_sha512


def test_rfc_profile_requires_request_type() -> None:
    packet = client.build_request(versions=(1,))
    packet.message.tags = [tag for tag in packet.message.tags if tag.tag != tags.TYPE]
    request = server.Request.from_bytes(packet.dump())
    with pytest.raises(PacketError, match="Missing TYPE"):
        request.validate(ProtocolProfile.from_version(1))


@pytest.mark.parametrize(
    ("version", "delegation_context"),
    [
        (DRAFT_VERSION_ZERO | 7, b"RoughTime v1 delegation signature\x00"),
        (DRAFT_VERSION_ZERO | 11, b"RoughTime v1 delegation signature--\x00"),
        (DRAFT_VERSION_ZERO | 12, b"RoughTime v1 delegation signature\x00"),
        (DRAFT_VERSION_ZERO | 15, b"RoughTime v1 delegation signature\x00"),
        (GOOGLE_ROUGHTIME_SENTINEL, b"RoughTime v1 delegation signature--\x00"),
    ],
)
def test_legacy_profiles_keep_signature_contexts(version: int, delegation_context: bytes) -> None:
    profile = ProtocolProfile.from_version(version)
    assert profile.version == version
    assert profile.response_context == b"RoughTime v1 response signature\x00"
    assert profile.delegation_context == delegation_context


def rfc_response(*, batched: bool) -> tuple[server.Server, bytes, bytes]:
    srv = server.Server.create(versions=(1,))
    raw = client.build_request(
        versions=(1,), public_key=server.public_key_bytes(srv.long_term_key)
    ).dump()
    if batched:
        response = server.handle_batch(srv, (raw,))[0]
        assert response is not None
    else:
        response = server.build_response(
            srv,
            nonce=server.Request.from_bytes(raw).nonce,
            profile=ProtocolProfile.from_version(1),
            midpoint=srv.get_time(),
            root=partial_sha512(b"\x00" + raw),
            path=[],
            index=0,
        )
    return srv, raw, response


@pytest.mark.parametrize("batched", [False, True])
def test_rfc_signatures_roundtrip(*, batched: bool) -> None:
    srv, raw, response = rfc_response(batched=batched)
    verified = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert verified.version == 1
    assert verified.verify(server.public_key_bytes(srv.long_term_key))


@pytest.mark.parametrize("signature", ["response", "delegation"])
def test_rfc_rejects_draft_signature_context(signature: str) -> None:
    srv, raw, response = rfc_response(batched=True)
    packet = Packet.from_bytes(response)
    if signature == "response":
        get_by_tag(packet.message.tags, tags.SIG).value = srv.delegated_key.sign(
            b"RoughTime v1 response signature\x00"
            + get_by_tag(packet.message.tags, tags.SREP).value
        )
    else:
        get_by_tag(packet.message.tags, tags.CERT).value = srv.certificates.certs[
            b"RoughTime v1 delegation signature\x00"
        ].to_bytes()
    verified = client.VerifiableResponse.from_packet(raw=packet.dump(), request=raw)
    with pytest.raises(VerificationError, match="signature invalid"):
        verified.verify(server.public_key_bytes(srv.long_term_key))


def test_rfc_version_grease_uses_response_context() -> None:
    srv, _raw, response = rfc_response(batched=True)
    message = Packet.from_bytes(response).message
    server.grease_change_version(srv, ProtocolProfile.from_version(1), message)
    srv.delegated_key.public_key().verify(
        get_by_tag(message.tags, tags.SIG).value,
        b"Roughtime v1 response signature\x00" + get_by_tag(message.tags, tags.SREP).value,
    )
