from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class Config:
    base_url: str
    email: str
    password: str
    collector_id: str
    log_path: str | None = None
    log_paths: tuple[str, ...] = field(default_factory=tuple)
    asset_name: str | None = None
    threshold: int = 10
    window_seconds: int = 60
    cooldown_seconds: int = 300

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
    return Config(
        base_url=data["base_url"],
        email=data["email"],
        password=data["password"],
        collector_id=data["collector_id"],
        log_path=log_path,
        log_paths=log_paths,
        asset_name=data.get("asset_name"),
        threshold=int(data.get("threshold", 10)),
        window_seconds=int(data.get("window_seconds", 60)),
        cooldown_seconds=int(data.get("cooldown_seconds", 300)),
    )
