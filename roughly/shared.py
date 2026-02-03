from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from cryptography.hazmat.primitives import hashes

from roughly.errors import RoughtimeError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, MutableSequence

    from roughly.models import Tag

MJD_UNIX_EPOCH = 40587
SECONDS_IN_A_DAY = 86400


PACKET_SIZE = 1024


ROUGHTIM = 0x4D49544847554F52
RESPONSE_CONTEXT_STRING = b"RoughTime v1 response signature\x00"
DELEGATION_CONTEXT_STRING = b"RoughTime v1 delegation signature\x00"
DELEGATION_CONTEXT_STRING_OLD = b"RoughTime v1 delegation signature--\x00"

DRAFT_VERSION_ZERO = 0x80000000

# the TYPE tag was introduced in draft-14
TYPE_FIRST_VERSION = DRAFT_VERSION_ZERO | 14

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


def build_supported_versions(start: int, end: int) -> tuple[int, ...]:
    # Build a tuple of supported Roughtime versions (inclusive of start and end)
    return tuple(sorted(DRAFT_VERSION_ZERO | v for v in range(start, end + 1)))


def split_into_chunks(data: bytes, chunk_size: int) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def always(x: T | None) -> T:  # noqa: UP047
    if x is None:
        raise RuntimeError("Expected non-None value")
    return x


def pick_delegation_string(version: int) -> bytes:
    # VDIFF: what? the context string got changed in draft-8 through draft-11
    # and then got changed back in draft-12
    delegation_context_string = DELEGATION_CONTEXT_STRING

    if DRAFT_VERSION_ZERO | 7 < version < DRAFT_VERSION_ZERO | 12:
        delegation_context_string = DELEGATION_CONTEXT_STRING_OLD
    return delegation_context_string


def pop_by_tag(tag_list: MutableSequence[Tag], tag_value: int) -> Tag:
    result = find_by_predicate(tag_list, lambda t: t.tag == tag_value)
    if result is not None:
        return tag_list.pop(result)
    ascii_repr = tag_value.to_bytes(4, "little").decode("ascii", errors="replace")
    raise RoughtimeError(f"Tag {ascii_repr} not found")


def pop_by_tag_optional(tag_list: MutableSequence[Tag], tag_value: int) -> Tag | None:
    result = find_by_predicate(tag_list, lambda t: t.tag == tag_value)
    if result is not None:
        return tag_list.pop(result)
    return None


def find_by_predicate(
    tag_list: MutableSequence[Tag], predicate: Callable[[Tag], bool]
) -> int | None:
    for i, tag in enumerate(tag_list):
        if predicate(tag):
            return i
    return None


def convert_mjd_to_unix(mjd: int) -> int:
    mjd_days = mjd >> 40
    microseconds = mjd & 0xFFFFFFFFFF
    return (mjd_days - MJD_UNIX_EPOCH) * SECONDS_IN_A_DAY + microseconds_to_seconds(microseconds)


def microseconds_to_seconds(microseconds: int) -> int:
    return microseconds // 1_000_000
