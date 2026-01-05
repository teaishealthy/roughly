# roughly

![Ruff logo](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)
![WIP](https://img.shields.io/badge/status-WIP-red?style=flat-square)

An asynchronous client library for the Roughtime protocol for Python.

Implements the Roughtime protocol as described in https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15, aka "IETF-Roughtime".
Draft versions 07 through 15 are supported.

## Quickstart

```python
import roughly

response = await roughly.send_request(
    host="roughtime.se"
    port=2002,
    public_key=base64.b64decode(b"S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="),
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

## Ecosystem

An example ecosystem file can be found at [ecosystem.json](ecosystem.json), I tried my best to include as many servers as I could find.

If you know of any other Roughtime servers, run your own server, or have updated public keys for any of the listed servers, please open a PR or an issue!


## Interoperability

The interopability matrix of `roughly` against Roughtime servers looks like this:

| Server                                                          |    |
|-----------------------------------------------------------------|----|
| [butterfield](https://github.com/signalsforgranted/butterfield) | ✅ |
| [cloudflare](https://github.com/cloudflare/roughtime)           | ✅ |
| [pyroughtime](https://github.com/dansarie/pyroughtime)          | ✅ |
| [roughenough](https://github.com/int08h/roughenough/)           | ⚠️ |
| [roughtimed](https://github.com/dansarie/roughtimed)            | ✅ |

⚠️ `roughenough` only expects version `0x8000000c` and does not ignore unknown versions.
Make sure to explicitly request only version `0x8000000c` when querying `roughenough` servers, i.e.:

```python
await roughly.send_request(
    # <snip!>
    versions=(0x8000000c,),
)
```

### draft-7

Support for draft-7 is limited, in the sense that `roughly` will fit responses from draft-7 servers into the draft-15 data structures.
This means that some fields that are not present in draft-8+ (such as DUT1, DTAI, and LEAP) will be missing.
Additionally draft-7 offered for the precision of radius to be in microseconds, while draft-8+ uses seconds, this precision will be lost when querying draft-7 servers, and be clamped to a minimum of one second.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
