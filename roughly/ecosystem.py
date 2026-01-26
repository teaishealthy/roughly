from __future__ import annotations

import asyncio
import base64
import itertools
import json
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypedDict

from roughly import (
    DRAFT_VERSION_ZERO,
    Response,
    RoughtimeError,
    VerificationError,
    partial_sha512,
    send_request,
)

if TYPE_CHECKING:
    from pathlib import Path

# Because Cloudflare's ecosystem file uses version strings instead of integers
VERSION_LOOKUP: dict[str, int] = {
    "IETF-Roughtime": DRAFT_VERSION_ZERO | 7,
    "Google-Roughtime": 3000600613,
}

logger = logging.getLogger(__name__)


class BadReport(RoughtimeError):  # noqa: N818
    """Raised when a malfeasance report is invalid."""


class MalfeasanceReport(TypedDict):
    rand: str
    request: str
    response: str
    publicKey: str


@dataclass
class Address:
    protocol: Literal["udp"]
    address: str


@dataclass
class Server:
    name: str
    version: int
    public_key_type: Literal["ed25519"]
    public_key: bytes
    addresses: list[Address]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Server:
        if isinstance(data["version"], str):
            data["version"] = VERSION_LOOKUP.get(data["version"], 0)

        return cls(
            name=data["name"],
            version=data["version"],
            public_key_type=data["publicKeyType"],
            public_key=base64.b64decode(data["publicKey"]),
            addresses=[
                Address(
                    protocol=addr["protocol"],
                    address=addr["address"],
                )
                for addr in data["addresses"]
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "publicKeyType": self.public_key_type,
            "publicKey": self.public_key.hex(),
            "addresses": [
                {
                    "protocol": addr.protocol,
                    "address": addr.address,
                }
                for addr in self.addresses
            ],
        }


def load_ecosystem(path: Path) -> list[Server]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    return [Server.from_dict(item) for item in data["servers"]]


async def _query_server(server: Server, *, timeout: float) -> tuple[Server, Response | None]:
    logger.debug(
        "Querying server %s at addresses: %s",
        server.name,
        ", ".join(addr.address for addr in server.addresses),
    )

    for addr in server.addresses:
        host, port_str = addr.address.rsplit(":", 1)
        port = int(port_str)
        try:
            async with asyncio.timeout(timeout):
                response = await send_request(
                    host,
                    port,
                    server.public_key,
                    versions=(server.version,),
                )
                return server, response
        except Exception:
            logger.exception("Failed to query server %s at address %s", server.name, addr.address)
            continue

    return server, None


async def pick_servers(servers: list[Server], *, timeout: float = 1.0) -> list[Server]:
    """Pick candidates for an ecosystem query.

    Args:
        servers (list[Server]): The servers to pick from.
        timeout (float, optional): The timeout for each server query. Defaults to 1.0.

    Returns:
        list[Server]: The selected servers for the query
    """
    tasks: list[asyncio.Task[tuple[Server, Response | None]]] = []
    for server in servers:
        tasks.append(asyncio.create_task(_query_server(server, timeout=timeout)))  # noqa: PERF401

    results: list[tuple[Server, Response | None]] = await asyncio.gather(*tasks)

    successful_servers: list[Server] = []
    for server, response in results:
        if response is not None:
            successful_servers.append(server)

    logger.debug("Picked %d/%d servers for query", len(successful_servers), len(servers))

    return successful_servers


async def query_servers(servers: list[Server]) -> list[tuple[Response, bytes]]:
    """Query multiple Roughtime servers for a measurement sequence.

    Args:
        servers (list[Server]): The servers to query.

    Raises:
        RoughtimeError: If querying any server fails.

    Returns:
        list[tuple[Response, bytes]]: The responses and random bytes used for each query.
    """
    logger.debug("Querying %d servers for measurement sequence", len(servers))

    responses: list[tuple[Response, bytes]] = []
    rand = os.urandom(32)
    nonce = rand

    for server in servers:
        for addr in server.addresses:
            host, port_str = addr.address.rsplit(":", 1)
            port = int(port_str)
            try:
                async with asyncio.timeout(5.0):
                    response = await send_request(
                        host,
                        port,
                        server.public_key,
                        nonce=nonce,
                        versions=(server.version,),
                    )
                    responses.append((response, rand))

                    rand = os.urandom(32)
                    nonce = partial_sha512(response.raw + rand)

            except Exception as e:
                raise RoughtimeError(f"Failed to query {host} at {addr.address}") from e
    return responses


def responses_consistent(
    responses: list[tuple[Response, bytes]],
) -> bool:
    """Check whether a set of Roughtime responses are consistent with each other.
    Only checks if the time intervals overlap.

    Args:
        responses (list[tuple[Response, bytes]]): The responses to check.

    Returns:
        bool: Whether the responses are consistent.
    """  # noqa: D205
    for (resp1, _), (resp2, _) in itertools.combinations(responses, 2):
        midp1 = resp1.signed_response.midpoint
        radi1 = resp1.signed_response.radius

        midp2 = resp2.signed_response.midpoint
        radi2 = resp2.signed_response.radius

        if abs(midp1 - midp2) > (radi1 + radi2):
            return False

    return True


def malfeasance_report(
    responses: list[tuple[Response, bytes]], servers: list[Server]
) -> list[MalfeasanceReport]:
    """Generate a malfeasance report from server responses. Does not check for malfeasance itself.

    Args:
        responses (list[tuple[Response, bytes]]): The responses from the servers.
        servers (list[Server]): The servers that were queried.

    Returns:
        list[MalfeasanceReport]: The generated malfeasance report.
    """
    report: list[MalfeasanceReport] = []
    for server, (response, rand) in zip(servers, responses, strict=True):
        report.append(
            {
                "rand": base64.b64encode(rand).decode("utf-8"),
                "request": base64.b64encode(response.request).decode("utf-8"),
                "response": base64.b64encode(response.raw).decode("utf-8"),
                "publicKey": base64.b64encode(server.public_key).decode("utf-8"),
            }
        )
    return report


def confirm_malfeasance(
    report: list[MalfeasanceReport],
) -> bool:
    """Confirm whether a malfeasance report indicates inconsistent responses.

    Args:
        report (list[MalfeasanceReport]): The malfeasance report to check.

    Raises:
        BadReport: If the malfeasance report is invalid.

    Returns:
        bool: Whether the malfeasance report indicates inconsistent responses.
    """
    responses: list[tuple[Response, bytes]] = []

    for entry in report:
        rand = base64.b64decode(entry["rand"])
        request = base64.b64decode(entry["request"])
        response_bytes = base64.b64decode(entry["response"])
        public_key = base64.b64decode(entry["publicKey"])

        response = Response.from_packet(
            raw=response_bytes,
            request=request,
        )

        try:
            response.verify(public_key)
        except VerificationError as e:
            raise BadReport("Invalid signature in malfeasance report") from e

        responses.append((response, rand))

    for idx, (current_response, current_rand) in enumerate(responses[1:], start=1):
        previous_response, _ = responses[idx - 1]

        expected_nonce = partial_sha512(previous_response.raw + current_rand)

        if current_response.nonce != expected_nonce:
            raise BadReport("Invalid nonce chaining in malfeasance report")

    return not responses_consistent(responses)
