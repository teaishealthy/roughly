from __future__ import annotations

import os
import struct
from typing import TYPE_CHECKING

import pytest

from roughly import client, server, tags
from roughly.errors import PacketError, VerificationError
from roughly.models import Message, Packet, SignedResponse, Tag
from roughly.shared import (
    DELEGATION_CONTEXT_STRING,
    DRAFT_VERSION_ZERO,
    PACKET_SIZE,
    RESPONSE_CONTEXT_STRING,
    ROUGHTIM,
    ProtocolProfile,
    partial_sha512,
)

DRAFT_15 = DRAFT_VERSION_ZERO | 15
DRAFT_14 = DRAFT_VERSION_ZERO | 14
DRAFT_11 = DRAFT_VERSION_ZERO | 11
PROFILE_15 = ProtocolProfile.from_version(DRAFT_15)

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric import ed25519


def make_server(**kwargs: object) -> server.Server:
    return server.Server.create(**kwargs)  # pyright: ignore[reportArgumentType]


def make_request(
    *,
    versions: tuple[int, ...] = (DRAFT_15,),
    nonce: bytes | None = None,
    public_key: bytes | None = None,
) -> bytes:
    return client.build_request(versions=versions, nonce=nonce, public_key=public_key).dump()


def roundtrip(srv: server.Server, raw: bytes) -> bytes:
    responses = server.handle_batch(srv, (raw,))
    assert len(responses) == 1
    assert responses[0] is not None, "Server unexpectedly dropped a valid request"
    return responses[0]


def get_tag(message: Message, tag_id: int) -> Tag:
    matches = [t for t in message.tags if t.tag == tag_id]
    assert matches, f"Tag {tag_id:#x} not present in message"
    return matches[0]


def replace_tag(message: Message, tag_id: int, value: bytes) -> None:
    get_tag(message, tag_id).value = value


def resign_srep(message: Message, delegated_key: ed25519.Ed25519PrivateKey) -> None:
    """Re-sign the SREP after modification."""
    srep = get_tag(message, tags.SREP)
    sig = get_tag(message, tags.SIG)
    sig.value = delegated_key.sign(RESPONSE_CONTEXT_STRING + srep.value)  # pyright: ignore[reportAttributeAccessIssue]


def remake_packet(message: Message, profile: ProtocolProfile = PROFILE_15) -> bytes:
    message.tags.sort(key=lambda t: t.tag)
    return Packet(message=message).dump(profile=profile)


# §4 Message Format & Wire Encoding


def test_request_uses_little_endian_uint32_for_versions() -> None:
    """§4.1.1: uint32 serialized little-endian."""
    raw = make_request(versions=(DRAFT_15,))
    msg = Packet.from_bytes(raw).message
    ver_value = get_tag(msg, tags.VER).value
    assert len(ver_value) == 4
    assert struct.unpack("<I", ver_value)[0] == DRAFT_15


def test_tags_are_4_octets() -> None:
    """§4.1.3: tags are 4-octet uint32 values."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    for tag in msg.tags:
        encoded = tag.tag.to_bytes(4, "little")
        assert len(encoded) == 4


def test_message_tag_offsets_are_4_byte_aligned() -> None:
    """§4.2: offsets are multiples of 4."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    for tag in msg.tags:
        assert len(tag.value) % 4 == 0, (
            f"Value for {tag.tag:#x} has length {len(tag.value)}, not 4-byte aligned"
        )


def test_message_tags_sorted_ascending() -> None:
    """§4.2: tags sorted ascending by uint32 value."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    tag_ids = [t.tag for t in msg.tags]
    assert tag_ids == sorted(tag_ids), "Request tags not sorted ascending"

    srv = make_server()
    resp = roundtrip(srv, raw)
    resp_msg = Packet.from_bytes(resp).message
    resp_ids = [t.tag for t in resp_msg.tags]
    assert resp_ids == sorted(resp_ids), "Response tags not sorted ascending"


def test_zero_length_values_are_allowed() -> None:
    """§4.2: values may have zero length."""
    msg = Message(
        tags=[
            Tag(tag=tags.NONC, value=os.urandom(32)),
            Tag(tag=tags.ZZZZ, value=b""),
        ]
    )
    encoded = msg.to_bytes()
    decoded = Message.from_bytes(encoded)
    zzzz = get_tag(decoded, tags.ZZZZ)
    assert zzzz.value == b""


def test_packet_uses_correct_magic() -> None:
    """§5 (L406-409): 8-byte magic 0x4d49544847554f52 ('ROUGHTIM')."""
    assert ROUGHTIM == 0x4D49544847554F52
    raw = make_request()
    magic = struct.unpack("<Q", raw[:8])[0]
    assert magic == ROUGHTIM
    # ASCII representation
    assert struct.pack("<Q", magic) == b"ROUGHTIM"


def test_packet_framing_includes_message_length() -> None:
    """§5: 4-byte uint32 message length follows the magic."""
    raw = make_request()
    (length,) = struct.unpack("<I", raw[8:12])
    assert length == len(raw) - 12


# §5.1 Requests


def test_request_contains_ver_nonc_type() -> None:
    """§5.1 L482, L484: request MUST contain VER, NONC, TYPE."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    tag_ids = {t.tag for t in msg.tags}
    assert tags.VER in tag_ids
    assert tags.NONC in tag_ids
    assert tags.TYPE in tag_ids


def test_request_includes_srv_when_public_key_given() -> None:
    """§5.1 L482: client SHOULD include SRV."""
    srv = make_server()
    pubkey = server.public_key_bytes(srv.long_term_key)
    raw = make_request(public_key=pubkey)
    msg = Packet.from_bytes(raw).message
    srv_tag = get_tag(msg, tags.SRV)
    assert srv_tag.value == partial_sha512(b"\xff" + pubkey)


def test_request_padded_to_1024_bytes_over_udp() -> None:
    """§5.1 L488: request size SHOULD be ≥1024 bytes; padded with ZZZZ."""
    raw = make_request()
    assert len(raw) >= PACKET_SIZE
    msg = Packet.from_bytes(raw).message
    tag_ids = {t.tag for t in msg.tags}
    assert tags.ZZZZ in tag_ids, "Request not padded with ZZZZ tag"


def test_request_type_is_zero() -> None:
    """§5.1.3 L536: TYPE in requests MUST be uint32 0."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    type_tag = get_tag(msg, tags.TYPE)
    assert struct.unpack("<I", type_tag.value)[0] == 0
    assert tags.TYPE_REQUEST == 0


def test_request_versions_sorted_and_unique() -> None:
    """§5.1.1 L517: VER MUST NOT repeat; MUST be sorted ascending."""
    versions = (DRAFT_14, DRAFT_15, DRAFT_11)
    raw = client.build_request(versions=tuple(sorted(versions))).dump()
    msg = Packet.from_bytes(raw).message
    ver_bytes = get_tag(msg, tags.VER).value
    parsed = struct.unpack(f"<{len(ver_bytes) // 4}I", ver_bytes)
    assert list(parsed) == sorted(set(parsed))
    assert len(parsed) == len(set(parsed))


def test_request_nonce_is_32_bytes_for_draft_15() -> None:
    """§5.1.2 L527: 32-byte nonce."""
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    nonc = get_tag(msg, tags.NONC)
    assert len(nonc.value) == PROFILE_15.nonce_size == 32


# §5.1 Server's handling of requests


def test_server_drops_request_below_1024_bytes() -> None:
    """§5.1 L493: responding to <1024-byte requests is OPTIONAL.

    This implementation drops them silently.
    """
    srv = make_server()
    short = b"\x00" * 512
    assert server.handle_batch(srv, (short,)) == [None]

@pytest.mark.parametrize("to_drop", ["VER", "NONC", "TYPE"])
def test_server_drops_request_missing_tag(to_drop: str) -> None:
    """§5.1 L484: server MUST ignore requests missing mandatory tags."""
    srv = make_server()
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    msg.tags = [tag for tag in msg.tags if tag.tag != getattr(tags, to_drop)]

    # remove ZZZZ and re-prepare
    msg.tags = [t for t in msg.tags if t.tag != tags.ZZZZ]
    msg.prepare()

    raw = Packet(message=msg).dump()
    assert server.handle_batch(srv, (raw,)) == [None]


def test_server_drops_request_missing_type_on_draft_14_plus() -> None:
    """§5.1 L484 / §5.1.3 L537: TYPE required for draft >=14."""
    srv = make_server()
    msg = Message(
        tags=[
            Tag(tag=tags.VER, value=struct.pack("<I", DRAFT_15)),
            Tag(tag=tags.NONC, value=os.urandom(32)),
        ]
    )
    msg.prepare()
    raw = Packet(message=msg).dump()
    assert server.handle_batch(srv, (raw,)) == [None]


def test_server_drops_request_with_nonzero_type() -> None:
    """§5.1.3 L537: server MUST ignore requests with TYPE != 0."""
    srv = make_server()
    msg = Message(
        tags=[
            Tag(tag=tags.VER, value=struct.pack("<I", DRAFT_15)),
            Tag(tag=tags.NONC, value=os.urandom(32)),
            Tag(tag=tags.TYPE, value=struct.pack("<I", 99)),
        ]
    )
    msg.prepare()
    raw = Packet(message=msg).dump()
    assert server.handle_batch(srv, (raw,)) == [None]


def test_server_drops_request_with_unknown_srv() -> None:
    """§5.2 L573: if SRV present and key unknown -> MUST ignore."""
    srv = make_server()
    raw = make_request(public_key=os.urandom(32))
    assert server.handle_batch(srv, (raw,)) == [None]


def test_server_drops_request_with_no_version_overlap() -> None:
    """§5.1.1 L522: if no overlap, server MAY respond or ignore.

    This implementation ignores.
    """
    srv = make_server()
    bogus_version = DRAFT_VERSION_ZERO | 0xABCD
    raw = make_request(versions=(bogus_version,))
    assert server.handle_batch(srv, (raw,)) == [None]


def test_server_ignores_unknown_tags_in_request() -> None:
    """§5.1 L483: server MUST ignore unknown tags."""
    srv = make_server()
    nonce = os.urandom(32)
    msg = Message(
        tags=[
            Tag(tag=tags.VER, value=struct.pack("<I", DRAFT_15)),
            Tag(tag=tags.NONC, value=nonce),
            Tag(tag=tags.TYPE, value=struct.pack("<I", 0)),
            # 'XXXX' is undefined
            Tag(tag=int.from_bytes(b"XXXX", "little"), value=b"\xde\xad\xbe\xef"),
        ]
    )
    msg.prepare()
    raw = Packet(message=msg).dump()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    resp.verify(server.public_key_bytes(srv.long_term_key))


def test_server_response_not_larger_than_request() -> None:
    """§5.1 L493 / L1136: server MUST NOT send responses larger than the request."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    assert len(response) <= len(raw)


# §5.2 Responses


def test_response_contains_required_tags() -> None:
    """§5.2: response contains SIG, NONC, TYPE, PATH, SREP, CERT, INDX."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    msg = Packet.from_bytes(response).message
    tag_ids = {t.tag for t in msg.tags}
    assert {tags.SIG, tags.NONC, tags.TYPE, tags.PATH, tags.SREP, tags.CERT, tags.INDX} <= tag_ids


def test_response_type_is_one() -> None:
    """§5.2.3 L650: response TYPE MUST be uint32 1."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    msg = Packet.from_bytes(response).message
    type_tag = get_tag(msg, tags.TYPE)
    assert struct.unpack("<I", type_tag.value)[0] == 1
    assert tags.TYPE_RESPONSE == 1


def test_response_path_at_most_32_hashes() -> None:
    """§5.2.4 L662: PATH MUST NOT contain more than 32 hash values."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    msg = Packet.from_bytes(response).message
    path = get_tag(msg, tags.PATH)
    assert len(path.value) % 32 == 0
    assert len(path.value) // 32 <= 32


def test_response_path_empty_for_single_request_batch() -> None:
    """A single-request batch produces an empty Merkle path."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    msg = Packet.from_bytes(response).message
    path = get_tag(msg, tags.PATH)
    assert path.value == b""


def test_response_radi_is_nonzero() -> None:
    """§5.2.5 L691: RADI MUST NOT be zero."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.signed_response.radius > 0


def test_response_radi_default_at_least_3() -> None:
    """§5.2.5 L694: without leap-second info, RADI SHOULD be ≥ 3."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.signed_response.radius >= 3


def test_response_vers_sorted_and_at_most_32() -> None:
    """§5.2.5 L701-704: VERS MUST NOT exceed 32 entries; sorted ascending."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    versions = list(resp.signed_response.versions)
    assert len(versions) <= 32
    assert versions == sorted(versions)


def test_response_vers_contains_ver() -> None:
    """§5.2.5 L701: VERS MUST contain the version in VER."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.signed_response.version in resp.signed_response.versions


def test_response_version_was_in_request_ver_list() -> None:
    """§5.2.5 L683: VER in response SHOULD be one of client-supplied versions."""
    srv = make_server()
    versions = (DRAFT_14, DRAFT_15)
    raw = make_request(versions=versions)
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.signed_response.version in versions


def test_response_midp_within_dele_bounds() -> None:
    """§5.2.6 L734-738: MIDP MUST be ≥ MINT and ≤ MAXT (verified via verify())."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    resp.verify(server.public_key_bytes(srv.long_term_key))
    dele = resp.certificate.delegation
    midp = resp.signed_response.midpoint
    assert dele.min_time <= midp <= dele.max_time


def test_response_nonce_echoes_request_nonce() -> None:
    """The NONC tag in response equals the NONC tag from the originating request."""
    srv = make_server()
    nonce = os.urandom(32)
    raw = make_request(nonce=nonce)
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.nonce == nonce


def test_server_with_no_srv_and_one_key_selects_that_key() -> None:
    """§5.2 L576: if no SRV and server has one key -> SHOULD select it."""
    srv = make_server()
    # Build request without public_key -> no SRV
    raw = make_request()
    msg = Packet.from_bytes(raw).message
    assert tags.SRV not in {t.tag for t in msg.tags}

    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    resp.verify(server.public_key_bytes(srv.long_term_key))


# §5.4 Response validation by client (verify())


def test_verify_succeeds_for_valid_response() -> None:
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    assert resp.verify(server.public_key_bytes(srv.long_term_key)) is True


def test_verify_rejects_bad_cert_signature() -> None:
    """§5.4: CERT signature must validate against long-term key."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    cert_tag = get_tag(packet.message, tags.CERT)
    cert_msg = Message.from_bytes(cert_tag.value)
    cert_sig = get_tag(cert_msg, tags.SIG)
    cert_sig.value = bytes(64)  # invalid signature
    cert_msg.tags.sort(key=lambda t: t.tag)
    cert_tag.value = cert_msg.to_bytes()
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    with pytest.raises(VerificationError) as exc_info:
        resp.verify(server.public_key_bytes(srv.long_term_key))
    assert exc_info.value.reason == "signature-certificate"


def test_verify_rejects_bad_response_signature() -> None:
    """§5.4: response SIG must validate against PUBK in DELE."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    sig_tag = get_tag(packet.message, tags.SIG)
    sig_tag.value = bytes(64)
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    with pytest.raises(VerificationError) as exc_info:
        resp.verify(server.public_key_bytes(srv.long_term_key))
    assert exc_info.value.reason == "signature-response"


def test_verify_rejects_midp_outside_delegation() -> None:
    """§5.4: MIDP must lie in [MINT, MAXT]."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    # Push midpoint far past MAXT and re-sign SREP so signature stays valid.
    srep_tag = get_tag(packet.message, tags.SREP)
    srep = SignedResponse.from_bytes(srep_tag.value, profile=PROFILE_15)
    srep.midpoint = 2**40  # well past any plausible MAXT
    srep_tag.value = srep.to_bytes()
    resign_srep(packet.message, srv.delegated_key)
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    with pytest.raises(VerificationError) as exc_info:
        resp.verify(server.public_key_bytes(srv.long_term_key))
    assert exc_info.value.reason == "key-age"


def test_verify_rejects_tampered_merkle_path() -> None:
    """§5.4: INDX+PATH must prove request leaf is under ROOT."""
    srv = make_server()
    # Use a batch >1 so PATH is non-empty.
    raws = [make_request(nonce=os.urandom(32)) for _ in range(2)]
    responses = server.handle_batch(srv, raws)
    assert all(r is not None for r in responses)

    raw, response = raws[0], responses[0]
    assert response is not None
    packet = Packet.from_bytes(response)
    path_tag = get_tag(packet.message, tags.PATH)
    # Flip a byte in the sibling hash.
    path_tag.value = bytes([path_tag.value[0] ^ 0xFF]) + path_tag.value[1:]
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    with pytest.raises(VerificationError) as exc_info:
        resp.verify(server.public_key_bytes(srv.long_term_key))
    assert exc_info.value.reason == "merkle"


def test_verify_rejects_tampered_root() -> None:
    """§5.4: ROOT must match Merkle tree derived from request + PATH."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    srep_tag = get_tag(packet.message, tags.SREP)
    srep = SignedResponse.from_bytes(srep_tag.value, profile=PROFILE_15)
    srep.root = bytes(32)  # all-zero root
    srep_tag.value = srep.to_bytes()
    resign_srep(packet.message, srv.delegated_key)
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    with pytest.raises(VerificationError) as exc_info:
        resp.verify(server.public_key_bytes(srv.long_term_key))
    assert exc_info.value.reason == "merkle"


def test_from_packet_rejects_nonce_mismatch() -> None:
    """The nonce in a response must echo the request's nonce."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    nonc_tag = get_tag(packet.message, tags.NONC)
    nonc_tag.value = os.urandom(32)
    tampered = remake_packet(packet.message)

    with pytest.raises(PacketError):
        client.VerifiableResponse.from_packet(raw=tampered, request=raw)


def test_from_packet_rejects_unrequested_response_version() -> None:
    """A response with a version not in the request VER list must be rejected."""
    srv = make_server()
    raw = make_request(versions=(DRAFT_15,))
    response = roundtrip(srv, raw)

    # Mutate request's VER list to omit DRAFT_15 entirely.
    req_packet = Packet.from_bytes(raw)
    ver_tag = get_tag(req_packet.message, tags.VER)
    ver_tag.value = struct.pack("<I", DRAFT_14)
    req_packet.message.tags.sort(key=lambda t: t.tag)
    bogus_request = Packet(message=req_packet.message).dump()

    with pytest.raises(PacketError):
        client.VerifiableResponse.from_packet(raw=response, request=bogus_request)


# §5.3 Merkle Tree


def test_merkle_leaf_uses_full_request_packet() -> None:
    """§5.3.1: leaf = H(0x00 || request_packet) for draft 12+."""
    raw = make_request()
    req = server.Request.from_bytes(raw)
    root, _ = server.build_merkle_tree(PROFILE_15, (req,))
    assert root == partial_sha512(b"\x00" + raw)


def test_merkle_internal_node_format() -> None:
    """§5.3.1: internal node = H(0x01 || left || right)."""
    raws = [make_request(nonce=os.urandom(32)) for _ in range(2)]
    reqs = [server.Request.from_bytes(r) for r in raws]
    root, levels = server.build_merkle_tree(PROFILE_15, reqs)

    left = partial_sha512(b"\x00" + raws[0])
    right = partial_sha512(b"\x00" + raws[1])
    expected_root = partial_sha512(b"\x01" + left + right)
    assert root == expected_root
    assert levels[0] == [left, right]


def test_merkle_index_bits_are_lsb_first() -> None:
    """§5.3.1: INDX bits least-significant first determine path direction."""
    srv = make_server()
    # 4-leaf tree gives a 2-bit INDX. Index 1 (binary 01) means: at level 0
    # the leaf is on the right (bit=1), at level 1 the subtree is on the left
    # (bit=0). The implementation in client._verify_merkle iterates LSB first.
    raws = [make_request(nonce=os.urandom(32)) for _ in range(4)]
    responses = server.handle_batch(srv, raws)
    assert all(r is not None for r in responses)

    for raw, response in zip(raws, responses, strict=True):
        assert response is not None
        resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
        # If LSB-first interpretation is wrong, verify() raises a merkle error.
        resp.verify(server.public_key_bytes(srv.long_term_key))


# §5.2.1 / §5.2.6 SIG semantics


def test_signature_contexts_are_zero_terminated() -> None:
    """§5.2.1: signature context strings are zero-terminated."""
    assert RESPONSE_CONTEXT_STRING.endswith(b"\x00")
    assert RESPONSE_CONTEXT_STRING == b"RoughTime v1 response signature\x00"
    assert DELEGATION_CONTEXT_STRING.endswith(b"\x00")
    assert DELEGATION_CONTEXT_STRING == b"RoughTime v1 delegation signature\x00"


# §7 Grease


def test_client_ignores_undefined_tags_in_response() -> None:
    """§7 L878: clients MUST ignore undefined tags."""
    srv = make_server()
    raw = make_request()
    response = roundtrip(srv, raw)

    packet = Packet.from_bytes(response)
    packet.message.tags.append(
        Tag(tag=int.from_bytes(b"XXXX", "little"), value=b"\xde\xad\xbe\xef"),
    )
    tampered = remake_packet(packet.message)

    resp = client.VerifiableResponse.from_packet(raw=tampered, request=raw)
    resp.verify(server.public_key_bytes(srv.long_term_key))


# Misc — VER/NONC echoed properly across versions


@pytest.mark.parametrize("version", [DRAFT_11, DRAFT_14, DRAFT_15])
def test_verify_succeeds_across_supported_versions(version: int) -> None:
    """A single client-supplied version produces a verifiable response."""
    srv = make_server()
    raw = make_request(versions=(version,))
    response = roundtrip(srv, raw)
    resp = client.VerifiableResponse.from_packet(raw=response, request=raw)
    resp.verify(server.public_key_bytes(srv.long_term_key))
