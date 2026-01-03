# roughly

![Ruff logo](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/teaishealthy/teaishealthy/refs/heads/main/ruff-badge.json&style=flat-square)
![WIP](https://img.shields.io/badge/status-WIP-red?style=flat-square)

An asynchronous client library for the Roughtime protocol for Python.

Implements the Roughtime protocol as described in https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-15, aka "IETF-Roughtime".
Draft versions 08 through 15 are supported.

## Quickstart

```python
import roughly

async def main():
    response = await roughly.send_request(
        host="roughtime.se"
        port=2002,
        public_key=base64.b64decode(b"S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI="),
    )
    # Requests are always verified before being returned

    print("Current time:", response.signed_response.midpoint)
```
