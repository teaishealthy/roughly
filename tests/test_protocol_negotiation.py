import pytest

from roughly import client, server
from roughly.shared import DRAFT_VERSION_ZERO, RFC_VERSION


def test_default_client_and_server_negotiate_rfc() -> None:
    srv = server.Server.create()
    raw = client.build_request().dump()
    response = server.handle_batch(srv, (raw,))[0]
    assert response is not None
    verified = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert verified.version == RFC_VERSION
    assert verified.verify(server.public_key_bytes(srv.long_term_key))


@pytest.mark.parametrize(
    ("client_versions", "server_versions", "expected"),
    [
        # RFC preference is independent of the order of offered versions.
        ((1, 0x8000000C), (1, 0x8000000C), 1),
        ((0x8000000C, 1), (1, 0x8000000C), 1),
        # RFC must be supported by both parties.
        ((0x8000000C,), (1, 0x8000000C), 0x8000000C),
        ((1, 0x8000000C), (0x8000000C,), 0x8000000C),
        ((1,), (0x8000000C,), None),
        # Preserve highest-common-draft fallback.
        ((0x8000000A, 0x8000000C, 0x8000000F), (0x8000000A, 0x8000000C), 0x8000000C),
    ],
)
def test_version_preference(
    client_versions: tuple[int, ...], server_versions: tuple[int, ...], expected: int | None
) -> None:
    assert server.select_version(client_versions, frozenset(server_versions)) == expected


@pytest.mark.parametrize("draft", [10, 11, 12, 13, 14, 15])
def test_default_server_accepts_draft_only_clients(draft: int) -> None:
    srv = server.Server.create()
    version = DRAFT_VERSION_ZERO | draft
    raw = client.build_request(versions=(version,)).dump()
    response = server.handle_batch(srv, (raw,))[0]
    assert response is not None
    verified = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert verified.version == version
    assert verified.verify(server.public_key_bytes(srv.long_term_key))


def test_default_client_accepts_draft_only_server() -> None:
    srv = server.Server.create(versions=(DRAFT_VERSION_ZERO | 12,))
    raw = client.build_request().dump()
    response = server.handle_batch(srv, (raw,))[0]
    assert response is not None
    verified = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert verified.version == DRAFT_VERSION_ZERO | 12
    assert verified.verify(server.public_key_bytes(srv.long_term_key))
