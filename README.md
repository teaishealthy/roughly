# roughly

![Ruff logo](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)
![WIP](https://img.shields.io/badge/status-WIP-red?style=flat-square)

An asynchronous client library for the Roughtime protocol for Python.

Implements the Roughtime protocol as described in https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15, aka "IETF-Roughtime".
Draft versions 08 through 15 are supported.

## Quickstart

```python
import roughly

response = await roughly.send_request(
    host="roughtime.se"
    port=2002,
    public_key=base64.b64decode(b"S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="),
)
# Requests are always verified before being returned

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
