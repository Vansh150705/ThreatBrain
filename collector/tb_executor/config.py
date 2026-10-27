from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class ExecutorConfig:
    base_url: str
    email: str | None = None
    password: str | None = None
    api_key: str | None = None
    poll_interval: int = 10
    dry_run: bool = True
    firewall: str = "auto"          # auto | iptables | windows | dry-run
    allow_private: bool = False
    allowlist: tuple[str, ...] = field(default_factory=tuple)
    enabled_actions: tuple[str, ...] = ("block_ip",)
    user_allowlist: tuple[str, ...] = field(default_factory=tuple)


def load_executor_config(path: str) -> ExecutorConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    api_key = data.get("api_key") or None
    email, password = data.get("email") or None, data.get("password") or None
    if not api_key and not (email and password):
        raise ValueError("config must set 'api_key' (an executor-scoped key, recommended) or both 'email' and 'password'")
    return ExecutorConfig(
        base_url=data["base_url"],
        email=email,
        password=password,
        api_key=api_key,
        poll_interval=int(data.get("poll_interval", 10)),
        dry_run=bool(data.get("dry_run", True)),
        firewall=data.get("firewall", "auto"),
        allow_private=bool(data.get("allow_private", False)),
        allowlist=tuple(data.get("allowlist", []) or []),
        enabled_actions=tuple(data.get("enabled_actions", ["block_ip"]) or ["block_ip"]),
        user_allowlist=tuple(data.get("user_allowlist", []) or []),
    )
