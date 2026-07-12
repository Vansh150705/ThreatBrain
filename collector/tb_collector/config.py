from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass
class Config:
    base_url: str
    email: str
    password: str
    collector_id: str
    log_path: str
    asset_name: str | None = None
    threshold: int = 10
    window_seconds: int = 60
    cooldown_seconds: int = 300


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Config(
        base_url=data["base_url"],
        email=data["email"],
        password=data["password"],
        collector_id=data["collector_id"],
        log_path=data["log_path"],
        asset_name=data.get("asset_name"),
        threshold=int(data.get("threshold", 10)),
        window_seconds=int(data.get("window_seconds", 60)),
        cooldown_seconds=int(data.get("cooldown_seconds", 300)),
    )
