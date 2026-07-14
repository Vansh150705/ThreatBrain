from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class ExecutorConfig:
    base_url: str
    email: str
    password: str
    poll_interval: int = 10
    dry_run: bool = True
    firewall: str = "auto"          # auto | iptables | windows | dry-run
    allow_private: bool = False
    allowlist: tuple[str, ...] = field(default_factory=tuple)


def load_executor_config(path: str) -> ExecutorConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return ExecutorConfig(
        base_url=data["base_url"],
        email=data["email"],
        password=data["password"],
        poll_interval=int(data.get("poll_interval", 10)),
        dry_run=bool(data.get("dry_run", True)),
        firewall=data.get("firewall", "auto"),
        allow_private=bool(data.get("allow_private", False)),
        allowlist=tuple(data.get("allowlist", []) or []),
    )
