from typing import Literal

__all__ = (
    "FormatError",
    "PacketError",
    "RoughtimeError",
    "RoughtimeErrorReason",
    "VerificationError",
)

RoughtimeErrorReason = Literal["merkle", "key-age", "signature-certificate", "signature-response"]


class RoughtimeError(Exception):
    """Represents a generic Roughtime error."""


class PacketError(RoughtimeError):
    """Represents an error in packet parsing."""


class FormatError(RoughtimeError):
    """Represents an error in packet formatting."""


class VerificationError(RoughtimeError):
    """Represents an error in response verification."""

    def __init__(self, message: str, *, reason: RoughtimeErrorReason) -> None:
        super().__init__(message)
        self.reason: RoughtimeErrorReason = reason
