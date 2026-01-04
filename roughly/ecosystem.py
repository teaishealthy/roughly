from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# Because Cloudflare's ecosystem file uses version strings instead of integers
VERSION_LOOKUP: dict[str, int] = {
    "IETF-Roughtime": 0x80000000 | 7,
    "Google-Roughtime": 3000600613,
}


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
