# roughly

[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)](https://github.com/astral-sh/ruff)\
[![Roughtime draft 07-15](https://img.shields.io/badge/draft%2007--15-f2d3ff?style=flat-square)](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15)
![WIP](https://img.shields.io/badge/WIP-ffb1b1?style=flat-square)

An asynchronous library for the Roughtime protocol for Python.

Implements the Roughtime protocol as described in https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15.

Draft versions 07 through 15 are supported for querying servers, and draft versions 10 through 15 are supported for running a server. Assuming the clients/servers properly ignore unknown fields.

## Quickstart

### Installation
You can install `roughly` from GitHub using your favorite package manager, for example with `pip`:

```bash
pip install "git+https://github.com/teaishealthy/roughly.git"
# or with the cli extra
pip install "git+https://github.com/teaishealthy/roughly.git#egg=project[cli]"
```

### As a CLI

#### Querying

You can use `roughly` as a command line tool to query Roughtime servers.
Install `roughly` with the `cli` extra using your favorite CLI package manager, for example with `uv` (or `pipx`):

```bash
# Assuming you cloned the repository
uv tool install .[cli]
pipx install .[cli]
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

### As a library

#### Querying

`roughly` can be used as an asynchronous library to query Roughtime servers from your own Python code.

```python
import roughly

response = await roughly.send_request(
    host="time.teax.dev",
    port=2002,
    public_key=base64.b64decode(b"84pMADvKUcSOq5RNbVRjVrjiU16Dxo2XV2Qkm+4DRTg=")
)
# Responses are always verified before being returned

print("Current time:", response.signed_response.midpoint)
```

You can also use the built-in ecosystem tools to query multiple servers and check for malfeasance as described in the RFC.

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

#### Running a server

You can also programmatically run your own Roughtime server:

```python
import roughly
import roughly.server

config = roughly.server.Config.create() # generates a new keypair
await roughly.server.serve(config)
```

Why? You can subclass `roughly.server.UDPHandler` and `roughly.server.Server` to implement custom behavior. Like a malfeasant server for testing:

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
| [roughenough](https://github.com/int08h/roughenough/) | ⚠️ |
| [roughtimed](https://github.com/dansarie/roughtimed) | ✅ |
| roughly | ✅ |

⚠️ `roughenough` only expects version `0x8000000c` and does not ignore unknown versions.
Make sure to explicitly request only version `0x8000000c` when querying `roughenough` servers, i.e.:

```python
await roughly.send_request(
    # <snip!>
    versions=(0x8000000c,),
)
```

### Roughly as a server

| Client | Result |
|---|---:|
| cloudflare | ✅ |
| craggy | ✅ |
| node-roughtime | ❌ |
| pyroughtime | ✅ |
| roughenough | ❌ |
| roughly | ✅ |
| vroughtime | ❌ |




### draft-7

Support for draft-7 is limited, in the sense that `roughly` will fit responses from draft-7 servers into the draft-15 data structures.
This means that some fields that are not present in draft-8+ (such as DUT1, DTAI, and LEAP) will be missing.
Additionally draft-7 offered for the precision of radius to be in microseconds, while draft-8+ uses seconds, this precision will be lost when querying draft-7 servers, and be clamped to a minimum of one second.

### VDIFF comments

Throughout the codebase, comments beginning with `# VDIFF` mark sections that accommodate differences between Roughtime protocol drafts. These annotations help track changes made for compatibility and make it easier to identify code adjusted for specific draft versions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
