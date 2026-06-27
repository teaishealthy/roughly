from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias, TypeVar

from cryptography.hazmat.primitives import hashes

from roughly.errors import RoughtimeError

if TYPE_CHECKING:
    from collections.abc import Iterable, MutableSequence

    from roughly.models import Tag

MJD_UNIX_EPOCH = 40587
SECONDS_IN_A_DAY = 86400


PACKET_SIZE = 1024


ROUGHTIM = 0x4D49544847554F52
RESPONSE_CONTEXT_STRING = b"RoughTime v1 response signature\x00"
DELEGATION_CONTEXT_STRING = b"RoughTime v1 delegation signature\x00"
DELEGATION_CONTEXT_STRING_OLD = b"RoughTime v1 delegation signature--\x00"

DRAFT_VERSION_ZERO = 0x80000000
LATEST_WIRE_VERSION = DRAFT_VERSION_ZERO | 12

# The actual value is not important, we just need a unique sentinel
# that doesn't make sense semantically
GOOGLE_ROUGHTIME_SENTINEL = int.from_bytes(b"Google Roughtime")


T = TypeVar("T")


def format_versions(versions: Iterable[int]) -> str:
    return ", ".join(f"{v:#x}" for v in versions)


def partial_sha512(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    full_hash = digest.finalize()
    return full_hash[:32]


def sha512_256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA512_256())
    digest.update(data)
    return digest.finalize()


def sha512(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA512())
    digest.update(data)
    return digest.finalize()


ProfileKey: TypeAlias = tuple[Callable[[bytes], bytes], bool]  # noqa: UP040


@dataclass(frozen=True)
class ProtocolProfile:
    """Collection of version-specific protocol parameters and behaviors."""

    version: int
    hasher: Callable[[bytes], bytes]
    leaf_from_request: bool
    """True (draft >=12): Merkle leaf input is the full request packet; False: nonce only."""
    delegation_context: bytes
    nonce_size: int
    packet_framing: bool
    """True for all draft versions; False for Google (raw message, no magic/len header)."""
    type_tag_required: bool
    """True for draft >=14: TYPE tag must be present in incoming requests."""
    ver_tag_in_response: bool
    """True for draft <=11: include VER tag in outgoing responses."""
    midpoint_in_microseconds: bool
    """True for Google: MIDP/RADI on the wire are in microseconds."""
    use_mjd: bool
    """True for draft-7: midpoint is encoded as MJD rather than Unix seconds."""
    cert_times_in_microseconds: bool
    """True for Google: MINT/MAXT in the delegation certificate are in microseconds."""

    sorted_versions: bool
    """True for draft >=12: listed versions must be sorted in ascending order"""

    @property
    def key(self) -> ProfileKey:
        return (self.hasher, self.leaf_from_request)

    @staticmethod
    def from_version(version: int) -> ProtocolProfile:
        """Return the ProtocolProfile for a given Roughtime version."""
        if version == 1:
            version = LATEST_WIRE_VERSION

        if version == GOOGLE_ROUGHTIME_SENTINEL:
            return ProtocolProfile(
                version=version,
                hasher=sha512,
                leaf_from_request=False,
                delegation_context=DELEGATION_CONTEXT_STRING_OLD,
                nonce_size=64,
                packet_framing=False,
                type_tag_required=False,
                ver_tag_in_response=False,
                midpoint_in_microseconds=True,
                use_mjd=False,
                cert_times_in_microseconds=True,
                sorted_versions=False,
            )

        if version <= DRAFT_VERSION_ZERO | 7:
            return ProtocolProfile(
                version=version,
                hasher=sha512_256,
                leaf_from_request=False,
                delegation_context=DELEGATION_CONTEXT_STRING,
                nonce_size=64,
                packet_framing=True,
                type_tag_required=False,
                ver_tag_in_response=True,
                midpoint_in_microseconds=False,
                use_mjd=version == DRAFT_VERSION_ZERO | 7,
                cert_times_in_microseconds=False,
                sorted_versions=False,
            )

        if version < DRAFT_VERSION_ZERO | 12:  # draft 8-11
            return ProtocolProfile(
                version=version,
                hasher=partial_sha512,
                leaf_from_request=False,
                delegation_context=DELEGATION_CONTEXT_STRING_OLD,
                nonce_size=32,
                packet_framing=True,
                type_tag_required=False,
                ver_tag_in_response=True,
                midpoint_in_microseconds=False,
                use_mjd=False,
                cert_times_in_microseconds=False,
                sorted_versions=False,
            )

        # draft 12+
        return ProtocolProfile(
            version=version,
            hasher=partial_sha512,
            leaf_from_request=True,
            delegation_context=DELEGATION_CONTEXT_STRING,
            nonce_size=32,
            packet_framing=True,
            type_tag_required=version >= DRAFT_VERSION_ZERO | 14,
            ver_tag_in_response=False,
            midpoint_in_microseconds=False,
            use_mjd=False,
            cert_times_in_microseconds=False,
            sorted_versions=True,
        )


def build_supported_versions(start: int, end: int) -> tuple[int, ...]:
    # Build a tuple of supported Roughtime versions (inclusive of start and end)
    return tuple(sorted(DRAFT_VERSION_ZERO | v for v in range(start, end + 1)))


VERSIONS_SUPPORTED = (1, *build_supported_versions(7, 15))


def split_into_chunks(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def always(x: T | None) -> T:  # noqa: UP047
    if x is None:
        raise RuntimeError("Expected non-None value")
    return x


def pop_by_tag(tag_list: MutableSequence[Tag], tag_value: int) -> Tag:
    result = index_by_tag(tag_list, tag_value)
    if result is not None:
        return tag_list.pop(result)
    ascii_repr = tag_value.to_bytes(4, "little").decode("ascii", errors="replace")
    raise RoughtimeError(f"Tag {ascii_repr} not found")


def pop_by_tag_optional(tag_list: MutableSequence[Tag], tag_value: int) -> Tag | None:
    result = index_by_tag(tag_list, tag_value)
    if result is not None:
        return tag_list.pop(result)
    return None


def find_by_tag(tag_list: Iterable[Tag], tag_value: int) -> Tag | None:
    for tag in tag_list:
        if tag.tag == tag_value:
            return tag
    return None


def index_by_tag(tag_list: Iterable[Tag], tag_value: int) -> int | None:
    for i, tag in enumerate(tag_list):
        if tag.tag == tag_value:
            return i
    return None


def convert_mjd_to_unix(mjd: int) -> int:
    mjd_days = mjd >> 40
    microseconds = mjd & 0xFFFFFFFFFF
    return (mjd_days - MJD_UNIX_EPOCH) * SECONDS_IN_A_DAY + microseconds_to_seconds(microseconds)


def microseconds_to_seconds(microseconds: int) -> int:
    return microseconds // 1_000_000
