# roughly

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)](https://github.com/astral-sh/ruff)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/teaishealthy/roughly/tests.yml?style=flat-square&label=tests)
![Coveralls](https://img.shields.io/coverallsCoverage/github/teaishealthy/roughly?style=flat-square)
[![Roughtime draft 07-19](https://img.shields.io/badge/draft%2007--19-f2d3ff?style=flat-square)](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-19)
![WIP](https://img.shields.io/badge/WIP-ffb1b1?style=flat-square)

An asynchronous implemenation of the Roughtime protocol for Python.

Implements the Roughtime protocol as described in https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-19.

Draft versions 07 through 19 are supported for querying servers.\
Draft versions 10 through 19 are supported for running a server. Also supports queries from Google Roughtime clients.


## Quickstart

### Installation
You can install `roughly` from PyPI using your favorite package manager, for example with `pip`:

```bash
pip install roughly
# or with the cli extra
pip install roughly[cli]
```

### As a CLI

#### Querying

You can use `roughly` as a command line tool to query Roughtime servers.
Install `roughly` with the `cli` extra using your favorite CLI package manager, for example with `uv` (or `pipx`):

```bash
uv tool install roughly[cli]
pipx install roughly[cli]
```

Then you can query a Roughtime server like so:

```bash
roughly query time.teax.dev 2002 84pMADvKUcSOq5RNbVRjVrjiU16Dxo2XV2Qkm+4DRTg=
```

Or run ecosystem queries (assuming you have an `ecosystem.json` file):

```bash
roughly ecosystem malfeasance
roughly ecosystem state
```

#### Running a server

You can also run your own Roughtime server using `roughly`.

First, generate a keypair:

```bash
roughly server keygen
```
This will output a .env file containing the server's private key.

You can then run the server like so:

```bash
ROUGHLY_SERVER_PRIVATE_KEY="your_private_key_here" roughly -v server run
```

By default, the server will bind to `0.0.0.0:2002`. You can change this using the `--host` and `--port` flags.
I recommend running the server with verbose logging enabled (`-v`), so you can see incoming requests and debug any issues.
Additionally you might want to consider turning off response greasing while testing using the `--no-grease` flag.

### As a library

#### Querying

`roughly` can be used as an asynchronous library to query Roughtime servers from your own Python code.

```python
import roughly.client

# <snip!>

response = await roughly.client.send_request(
    host="time.teax.dev",
    port=2002,
    public_key=base64.b64decode(b"84pMADvKUcSOq5RNbVRjVrjiU16Dxo2XV2Qkm+4DRTg="),
)
midpoint = response.signed_response.midpoint
radius = response.signed_response.radius
print(f"time: {midpoint} ± {radius}s")
```

`send_request` verifies the response before returning. Any failure raises `roughly.errors.VerificationError`; malformed packets raise `PacketError`. Both inherit from `RoughtimeError`. Once you have a response, true time is somewhere in the range `[midpoint - radius, midpoint + radius]`.

An *ecosystem* is a list of servers a client can query.
`roughly.ecosystem` provides a flow for querying them and checking for disagreement:

```python
from pathlib import Path
import json

from roughly.ecosystem import (
    confirm_malfeasance,
    load_ecosystem,
    malfeasance_report,
    pick_servers,
    query_servers,
)

ecosystem = load_ecosystem(Path("ecosystem.json"))
selected_servers = await pick_servers(ecosystem)
responses = await query_servers(selected_servers)
report = malfeasance_report(responses, selected_servers)

if confirm_malfeasance(report):
    print("something scary is going on!")
    with open("malfeasance_report.json", "w") as f:
        json.dump(report, f, indent=2)
```

`pick_servers` filters down to servers that are actually reachable right now. `query_servers` returns one `(VerifiableResponse, raw_bytes)` per server. `confirm_malfeasance` returns true when the responses can't all be true at the same time.

#### Running a server

You can also programmatically run your own Roughtime server. `Server.create()` mints a long-term ed25519 keypair on each call, so for any server clients should be able to keep talking to across restarts, pass `private_key=...` with a key you've persisted yourself:

```python
import roughly.server

server = roughly.server.Server.create() # generates a fresh keypair
await roughly.server.serve(server)
```

The reason to use the library directly instead of the CLI is that both `roughly.server.Server` and `roughly.server.UDPHandler` are designed to be extended. A sample use case is a deliberately malfeasant server:

```python
import roughly
import roughly.server

class ScaryServer(roughly.server.Server):
    @staticmethod
    def get_time() -> int:
        # return a wrong-ish time
        return int(time.time()) + random.randint(-3600, 3600)

await roughly.server.serve(ScaryServer.create())
```

## Ecosystem

An example ecosystem file can be found at [ecosystem.json](ecosystem.json), I tried my best to include as many servers as I could find.

If you know of any other Roughtime servers, run your own server, or have updated public keys for any of the listed servers, please open a PR or an issue!


## Interoperability

The interopability matrix of `roughly` against Roughtime servers looks like this:

### Roughly as a client

| Server | Result |
|---|---:|
| [butterfield](https://github.com/signalsforgranted/butterfield) | ✅ |
| [cloudflare](https://github.com/cloudflare/roughtime) | ✅ |
| [pyroughtime](https://github.com/dansarie/pyroughtime) | ✅ |
| [roughenough](https://github.com/int08h/roughenough/) | ✅ |
| [roughtimed](https://github.com/dansarie/roughtimed) | ✅ |
| roughly | ✅ |
| [tannerryan-roughtime](https://github.com/tannerryan/roughtime) | ✅ |



### Roughly as a server

| Client | Result |
|---|---:|
| cloudflare | ✅ |
| craggy | ✅ |
| node-roughtime | ✅ |
| pyroughtime | ✅ |
| roughenough | ✅ |
| roughly | ✅ |
| tannerryan-roughtime | ✅ |
| vroughtime | ✅ |




### draft-7

Support for draft-7 is limited, in the sense that `roughly` will fit responses from draft-7 servers into the draft-15 data structures.
This means that some fields that are not present in draft-8+ (such as DUT1, DTAI, and LEAP) will be missing.
Additionally draft-7 offered for the precision of radius to be in microseconds, while draft-8+ uses seconds, this precision will be lost when querying draft-7 servers, and be clamped to a minimum of one second.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
