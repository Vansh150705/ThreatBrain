from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class Config:
    base_url: str
    collector_id: str
    email: str | None = None
    password: str | None = None
    api_key: str | None = None
    log_path: str | None = None
    log_paths: tuple[str, ...] = field(default_factory=tuple)
    asset_name: str | None = None
    threshold: int = 10
    window_seconds: int = 60
    cooldown_seconds: int = 300
    async_ingest: bool = True
    spool_path: str = "tb-collector-spool.jsonl"
    spool_max_items: int = 2000

    def effective_paths(self) -> list[str]:
        """The log files to watch — log_paths if given, else the single log_path."""
        if self.log_paths:
            return list(self.log_paths)
        return [self.log_path] if self.log_path else []


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    log_path = data.get("log_path")
    log_paths = tuple(data.get("log_paths", []) or [])
    if not log_path and not log_paths:
        raise KeyError("config must set 'log_path' or 'log_paths'")
    api_key = data.get("api_key") or None
    email, password = data.get("email") or None, data.get("password") or None
    if not api_key and not (email and password):
        raise ValueError("config must set 'api_key' (recommended) or both 'email' and 'password'")
    return Config(
        base_url=data["base_url"],
        collector_id=data["collector_id"],
        email=email,
        password=password,
        api_key=api_key,
        log_path=log_path,
        log_paths=log_paths,
        asset_name=data.get("asset_name"),
        threshold=int(data.get("threshold", 10)),
        window_seconds=int(data.get("window_seconds", 60)),
        cooldown_seconds=int(data.get("cooldown_seconds", 300)),
        async_ingest=bool(data.get("async_ingest", True)),
        spool_path=str(data.get("spool_path", "tb-collector-spool.jsonl")),
        spool_max_items=int(data.get("spool_max_items", 2000)),
    )
