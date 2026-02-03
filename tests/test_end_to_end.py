import base64
import contextlib
from collections.abc import AsyncGenerator

import pytest

import roughly.client
import roughly.ecosystem
import roughly.server

ROUGHLY_PRIVATE_KEY = base64.b64decode("Yhy96f0LvaDI9KSSYs5RMSs1+gPw3EkQeXPU/UBV5es=")
SERVER = roughly.ecosystem.Server.from_dict(
    {
        "name": "localhost",
        "version": max(roughly.server.CLIENT_VERSIONS_SUPPORTED),
        "publicKeyType": "ed25519",
        "publicKey": "eEBQPwhCxHJ2nJNra33/dGOuUx4VxUFwwROiw4RQ67Q=",
        "addresses": [{"protocol": "udp", "address": "127.0.0.1:2002"}],
    }
)


@contextlib.asynccontextmanager
async def run_server() -> AsyncGenerator[None, None]:
    server = roughly.server.Server.create(private_key=ROUGHLY_PRIVATE_KEY)

    transport = await roughly.server._start_server(  # pyright: ignore[reportPrivateUsage]
        server, host="127.0.0.1", port=2002, handler=roughly.server.UDPHandler
    )

    try:
        yield
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_server_and_client() -> None:
    async with run_server():
        await roughly.client.send_request("127.0.0.1", 2002, SERVER.public_key)


@pytest.mark.asyncio
async def test_ecosystem() -> None:
    async with run_server():
        selected_servers = await roughly.ecosystem.pick_servers([SERVER])
        responses = await roughly.ecosystem.query_servers(selected_servers)
        report = roughly.ecosystem.malfeasance_report(responses, selected_servers)

        if roughly.ecosystem.confirm_malfeasance(report):
            raise RuntimeError("Malfeasance confirmed in test_ecosystem")
