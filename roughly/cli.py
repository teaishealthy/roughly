import asyncio
import base64
import json
import logging
import time
import traceback
from pathlib import Path
from typing import Any, cast

import click

import roughly
import roughly.ecosystem
import roughly.server

# ruff: noqa: FBT001 FBT002 PLR0913

REASON_EXPLANATIONS: dict[roughly.RoughtimeErrorReason, str] = {
    "key-age": "The delegated signing key is too old.",
    "merkle": (
        "The server signed timestamps for multiple requests at once."
        " This response could not be proven to be part of the signed batch."
    ),
    "signature-response": "The server's response signature could not be verified.",
    "signature-certificate": "The server's delegation certificate signature could not be verified.",
}


@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable logging",
)
@click.group()
def cli(verbose: bool) -> None:
    """roughly: A Roughtime client."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)


async def _query(
    host: str, port: int, public_key: bytes, *, timeout: float
) -> roughly.VerifiableResponse:
    async with asyncio.timeout(timeout):
        return await roughly.send_request(host, port, public_key)


async def _very_dangerously_query(
    host: str, port: int, public_key: bytes | None, *, timeout: float
) -> roughly.VerifiableResponse:
    async with asyncio.timeout(timeout):
        return await roughly.very_dangerously_send_request_and_do_not_verify(
            host,
            port,
            public_key,
        )


@cli.command()
@click.argument("host")
@click.argument("port", type=int, default=2002)
@click.argument("public-key", required=False)
@click.option("--terse", is_flag=True, help="Only output the time")
@click.option("--timeout", type=float, default=5.0, help="Request timeout in seconds")
@click.option(
    "--very-dangerously-disable-verification",
    is_flag=True,
    help="Disable response verification. Only use this if you ABSOLUTELY know what you're doing!",
)
def query(
    host: str,
    port: int,
    public_key: str | None,
    terse: bool,
    timeout: float,
    very_dangerously_disable_verification: bool,
) -> None:
    """Query a Roughtime server for the current time."""
    query_function = _query
    if very_dangerously_disable_verification:
        query_function = _very_dangerously_query
    elif public_key is None:
        click.echo(
            "Public key is required unless --very-dangerously-disable-verification is set",
            err=True,
        )
        return

    try:
        # The cast here is needed, but safe, because of the check above.
        key_bytes = None
        if public_key is not None:
            key_bytes = base64.b64decode(public_key)
        response = asyncio.run(query_function(host, port, cast(Any, key_bytes), timeout=timeout))
    except TimeoutError:
        click.echo("Request timed out", err=True)
        return
    except roughly.VerificationError as e:
        traceback.print_exc()
        click.echo()
        click.echo("Response received but rejected during verification", err=True)
        explanation = REASON_EXPLANATIONS.get(e.reason)
        if explanation:
            click.echo(f"{e.reason}: {explanation}", err=True)
        else:
            click.echo(f"Reason: {e.reason}", err=True)
        return
    except roughly.RoughtimeError:
        traceback.print_exc()
        click.echo()
        click.echo("A Roughtime protocol error occured while querying the server", err=True)
        click.echo("If you believe this is a bug, please file an issue", err=True)
        return

    unix_time = response.signed_response.midpoint
    radius = response.signed_response.radius
    if terse:
        click.echo(unix_time)
    else:
        click.echo(f"Current time: {unix_time} ± {radius} seconds")


@cli.group()
def ecosystem() -> None:
    """Commands for working with Roughtime ecosystems."""


async def _ecosystem_state(ecosystem_path: Path) -> None:
    ecosystem = roughly.ecosystem.load_ecosystem(ecosystem_path)
    selected_servers = await roughly.ecosystem.pick_servers(ecosystem)

    click.echo(
        f"Out of {len(ecosystem)} servers, {len(selected_servers)} yielded proper responses."
    )
    failed_to_select = {server.name for server in ecosystem} - {
        server.name for server in selected_servers
    }

    if failed_to_select:
        click.echo("Failed to select the following servers:")
        for server in failed_to_select:
            click.echo(f"- {server}")

    click.echo("\nAvailable servers:")
    for server in selected_servers:
        click.echo(f"- {server.name} ({server.version:#x})")

    tasks: list[
        asyncio.Task[tuple[roughly.ecosystem.Server, roughly.VerifiableResponse | None]]
    ] = []

    for server in selected_servers:
        task = asyncio.create_task(
            roughly.ecosystem._query_server(  # pyright: ignore[reportPrivateUsage]
                server,
                timeout=1.0,
            )
        )
        tasks.append(task)

    results = await asyncio.gather(*tasks)

    current_time = time.time()
    click.echo(f"\nAt {current_time:.0f} (machine time) received responses from:")
    for server, response in results:
        if response is not None:
            server_time = response.signed_response.midpoint
            radius = response.signed_response.radius
            click.echo(f"- {server.name}: time={server_time} ± {radius} seconds")


@ecosystem.command()
@click.argument(
    "ecosystem-path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("ecosystem.json"),
)
def state(ecosystem_path: Path) -> None:
    """Evaluate the state of a Roughtime ecosystem."""
    asyncio.run(_ecosystem_state(ecosystem_path))


async def _malfeasance_test(
    ecosystem_path: Path,
    always_write: bool = False,
    report_location: Path | None = None,
) -> None:
    report_location = report_location or Path("malfeasance_report.json")
    ecosystem = roughly.ecosystem.load_ecosystem(ecosystem_path)
    selected_servers = await roughly.ecosystem.pick_servers(ecosystem)
    click.echo("Selected servers for malfeasance testing:")
    for server in selected_servers:
        click.echo(f"- {server.name}")
    responses = await roughly.ecosystem.query_servers(selected_servers)
    report = roughly.ecosystem.malfeasance_report(responses, selected_servers)

    if had_malfeasance := roughly.ecosystem.confirm_malfeasance(report):
        click.echo(f"Malfeasance detected. Writing report to '{report_location}'.")
        with report_location.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    else:
        click.echo("No malfeasance detected.")

    if not had_malfeasance and always_write:
        with report_location.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"Report saved to '{report_location}' (no malfeasance detected).")


@ecosystem.command()
@click.option(
    "--always-write",
    is_flag=True,
    help="Always write a malfeasance report, even if no malfeasance is detected",
)
@click.option(
    "--report-location",
    type=click.Path(path_type=Path),
    help="Location to save the malfeasance report",
)
@click.option(
    "--ecosystem-path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("ecosystem.json"),
    help="Path to the ecosystem JSON file",
)
def malfeasance(always_write: bool, report_location: Path | None, ecosystem_path: Path) -> None:
    """Run a malfeasance test on the Roughtime ecosystem."""
    asyncio.run(
        _malfeasance_test(
            always_write=always_write,
            report_location=report_location,
            ecosystem_path=ecosystem_path,
        )
    )


@cli.group()
def server() -> None:
    """Commands for running a Roughtime server."""


@server.command(name="run")
@click.option("--host", default="0.0.0.0", help="Host to bind to")  # noqa: S104
@click.option("--port", "-p", default=2002, type=int, help="Port to bind to")
@click.option(
    "--private-key",
    type=str,
    help="Base64-encoded 32-byte Ed25519 private key. If not provided, generates a new key.",
    envvar="ROUGHLY_PRIVATE_KEY",
)
@click.option(
    "--radius",
    default=3,
    type=int,
    help="Uncertainty radius in seconds",
)
@click.option(
    "--validity-seconds",
    default=None,
    type=int,
    help="Validity period for the delegated key in seconds. "
    "If not set, defaults to 3600 seconds (1 hour).",
)
def server_run(
    host: str,
    port: int,
    private_key: str | None,
    radius: int,
    validity_seconds: int | None,
) -> None:
    """Run a Roughtime server."""
    key_bytes = base64.b64decode(private_key) if private_key else None

    config = roughly.server.Server.create(
        key_bytes,
        validity_seconds=validity_seconds,
        radius=radius,
    )

    pub_bytes = roughly.server.public_key_bytes(config.long_term_key)
    public_key_b64 = base64.b64encode(pub_bytes).decode()
    click.echo(f"Server public key (base64): {public_key_b64}")
    click.echo(f"Starting Roughtime server on {host}:{port}")

    try:
        asyncio.run(roughly.server.serve(config, host, port))
    except KeyboardInterrupt:
        click.echo("\nServer stopped.")


@server.command(name="keygen")
def server_keygen() -> None:
    """Generate a new Ed25519 key pair for the server."""
    key = roughly.server.generate_key()
    private_key_bytes = key.private_bytes_raw()
    pub_key_bytes = roughly.server.public_key_bytes(key)
    output_data = f"ROUGHLY_PRIVATE_KEY={base64.b64encode(private_key_bytes).decode()}"

    path = Path(".env")
    if path.exists() and not click.confirm(
        "'.env' file already exists. Overwrite?", default=False, show_default=True
    ):
        click.echo("Aborting key generation.")
        return

    with path.open("w", encoding="utf-8") as f:
        f.write(output_data + "\n")

    click.echo(f"Public key (base64): {base64.b64encode(pub_key_bytes).decode()}")
    click.echo(f"Private key saved to '{path}'. Keep it secret!")


if __name__ == "__main__":
    cli()
