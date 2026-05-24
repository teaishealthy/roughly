from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import socket
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import roughly.cli
import roughly.client
import roughly.errors
import roughly.server

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator

ROUGHLY_PRIVATE_KEY = base64.b64decode("Yhy96f0LvaDI9KSSYs5RMSs1+gPw3EkQeXPU/UBV5es=")
ROUGHLY_PUBLIC_KEY_B64 = "eEBQPwhCxHJ2nJNra33/dGOuUx4VxUFwwROiw4RQ67Q="


def _find_free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def background_server(port: int) -> Iterator[None]:
    ready = threading.Event()
    loop = asyncio.new_event_loop()
    stop = asyncio.Event()

    async def main() -> None:
        server = roughly.server.Server.create(private_key=ROUGHLY_PRIVATE_KEY)
        transport = await roughly.server._start_server(  # pyright: ignore[reportPrivateUsage]
            lambda: roughly.server.UDPHandler(server),
            host="127.0.0.1",
            port=port,
        )
        ready.set()
        try:
            await stop.wait()
        finally:
            transport.close()

    def run() -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(main())
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        finally:
            loop.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    assert ready.wait(timeout=0.1), "Server never started"
    try:
        yield
    finally:
        loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=0.1)


@pytest.fixture(autouse=True)
def _silence_logging() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def server_port() -> Generator[int, None, None]:
    port = _find_free_udp_port()
    with background_server(port):
        yield port


def test_query_success(runner: CliRunner, server_port: int) -> None:
    result = runner.invoke(
        roughly.cli.cli,
        ["query", "127.0.0.1", str(server_port), ROUGHLY_PUBLIC_KEY_B64],
    )
    assert result.exit_code == 0, result.output
    assert "Current time:" in result.output
    assert "seconds" in result.output


def test_query_terse(runner: CliRunner, server_port: int) -> None:
    result = runner.invoke(
        roughly.cli.cli,
        ["query", "--terse", "127.0.0.1", str(server_port), ROUGHLY_PUBLIC_KEY_B64],
    )
    assert result.exit_code == 0, result.output
    line = result.output.strip()
    assert line.isdigit()


def test_query_missing_key_errors(runner: CliRunner) -> None:
    result = runner.invoke(roughly.cli.cli, ["query", "127.0.0.1", "2002"])
    assert result.exit_code == 0
    assert "Public key is required" in result.output


def test_query_disable_verification(runner: CliRunner, server_port: int) -> None:
    result = runner.invoke(
        roughly.cli.cli,
        [
            "query",
            "--very-dangerously-disable-verification",
            "127.0.0.1",
            str(server_port),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Current time:" in result.output


def test_query_timeout(runner: CliRunner) -> None:
    async def hang(*_args: Any, **_kwargs: Any) -> Any:
        await asyncio.sleep(10)

    with patch.object(roughly.client, "send_request", hang):
        result = runner.invoke(
            roughly.cli.cli,
            [
                "query",
                "--timeout",
                "0.05",
                "127.0.0.1",
                "2002",
                ROUGHLY_PUBLIC_KEY_B64,
            ],
        )

    assert result.exit_code == 0
    assert "timed out" in result.output


def test_query_verification_error_explained(runner: CliRunner) -> None:
    err = roughly.errors.VerificationError("bad sig", reason="signature-response")

    async def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise err

    with patch.object(roughly.cli, "_query", boom):
        result = runner.invoke(
            roughly.cli.cli,
            ["query", "127.0.0.1", "2002", ROUGHLY_PUBLIC_KEY_B64],
        )

    assert result.exit_code == 0
    assert "rejected during verification" in result.output
    assert "signature-response" in result.output
    assert roughly.cli.REASON_EXPLANATIONS["signature-response"] in result.output


def test_query_roughtime_error(runner: CliRunner) -> None:
    async def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise roughly.errors.RoughtimeError("bad packet")

    with patch.object(roughly.cli, "_query", boom):
        result = runner.invoke(
            roughly.cli.cli,
            ["query", "127.0.0.1", "2002", ROUGHLY_PUBLIC_KEY_B64],
        )

    assert result.exit_code == 0
    assert "Roughtime protocol error" in result.output


def test_server_keygen_writes_env(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(roughly.cli.cli, ["server", "keygen"])
        assert result.exit_code == 0, result.output
        assert "Public key" in result.output

        env = Path(".env").read_text(encoding="utf-8")
        assert env.startswith("ROUGHLY_PRIVATE_KEY=")
        private_b64 = env.split("=", 1)[1].strip()
        assert len(base64.b64decode(private_b64)) == 32


def test_server_keygen_refuses_overwrite(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path(".env").write_text("ROUGHLY_PRIVATE_KEY=existing\n", encoding="utf-8")
        result = runner.invoke(roughly.cli.cli, ["server", "keygen"], input="n\n")
        assert result.exit_code == 0
        assert "Aborting" in result.output
        assert Path(".env").read_text(encoding="utf-8") == "ROUGHLY_PRIVATE_KEY=existing\n"


def test_server_keygen_accepts_overwrite(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path(".env").write_text("ROUGHLY_PRIVATE_KEY=existing\n", encoding="utf-8")
        result = runner.invoke(roughly.cli.cli, ["server", "keygen"], input="y\n")
        assert result.exit_code == 0, result.output
        new_contents = Path(".env").read_text(encoding="utf-8")
        assert "existing" not in new_contents
        assert new_contents.startswith("ROUGHLY_PRIVATE_KEY=")


def _write_ecosystem(path: Path, port: int) -> None:
    data = cast(
        Any,
        {
            "servers": [
                {
                    "name": "localhost",
                    "version": max(roughly.server.CLIENT_VERSIONS_SUPPORTED),
                    "publicKeyType": "ed25519",
                    "publicKey": ROUGHLY_PUBLIC_KEY_B64,
                    "addresses": [{"protocol": "udp", "address": f"127.0.0.1:{port}"}],
                }
            ]
        },
    )
    path.write_text(json.dumps(data), encoding="utf-8")


def test_ecosystem_state(runner: CliRunner, server_port: int) -> None:
    with runner.isolated_filesystem():
        _write_ecosystem(Path("ecosystem.json"), server_port)
        result = runner.invoke(roughly.cli.cli, ["ecosystem", "state"])
        assert result.exit_code == 0, result.output
        assert "Available servers:" in result.output
        assert "localhost" in result.output


def test_ecosystem_malfeasance_clean(runner: CliRunner, server_port: int) -> None:
    with runner.isolated_filesystem():
        _write_ecosystem(Path("ecosystem.json"), server_port)
        result = runner.invoke(roughly.cli.cli, ["ecosystem", "malfeasance"])
        assert result.exit_code == 0, result.output
        assert "No malfeasance detected." in result.output
        assert not Path("malfeasance_report.json").exists()


def test_ecosystem_malfeasance_always_write(runner: CliRunner, server_port: int) -> None:
    with runner.isolated_filesystem():
        _write_ecosystem(Path("ecosystem.json"), server_port)
        result = runner.invoke(
            roughly.cli.cli,
            ["ecosystem", "malfeasance", "--always-write"],
        )
        assert result.exit_code == 0, result.output
        report_path = Path("malfeasance_report.json")
        assert report_path.exists()
        json.loads(report_path.read_text(encoding="utf-8"))
