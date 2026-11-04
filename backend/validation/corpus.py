"""Load scenarios from the dataset registry (datasets.yaml). Every scenario carries its split; nothing is pooled."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
SCEN = ROOT / "scenarios"
REGISTRY = ROOT / "datasets.yaml"


MISSING: list[str] = []      # optional external datasets that were not present (reported, never silently skipped)


def registry() -> dict[str, Any]:
    return yaml.safe_load(REGISTRY.read_text(encoding="utf-8"))


def load_corpus(splits: set[str] | None = None, roles: set[str] | None = None) -> list[dict[str, Any]]:
    reg = registry()
    out: list[dict[str, Any]] = []
    for src in reg["sources"]:
        if splits and src["split"] not in splits:
            continue
        if roles and src["role"] not in roles:
            continue
        path = SCEN / src["file"]
        if src.get("optional") and not path.exists():
            if src["file"] not in MISSING:
                MISSING.append(src["file"])
            continue
        items = yaml.safe_load(path.read_text(encoding="utf-8"))["scenarios"]
        for sc in items:
            sid = str(sc["id"])
            if src.get("prefix") and not sid.startswith(src["prefix"]):
                continue
            if src.get("art_split") and sc.get("split") != src["art_split"]:
                continue
            if src.get("prefix_not") and sid.startswith(src["prefix_not"]):
                continue
            if src["role"] == "adversarial":
                role = "benign" if sc.get("label") == "benign" else "attack"
                family = sc.get("family")
                kind = "adversarial"
            elif src["role"] == "chain":
                role = "chain_negative" if "forbid_correlation" in sc else "chain"
                family, kind = None, "chain"
            elif src["role"] == "behavior":
                role = "behavior_attack" if sc.get("label") == "attack" else "behavior_benign"
                family, kind = None, "behavior"
            else:
                role, family, kind = src["role"], sc.get("family"), "event"
            out.append({**sc, "split": src["split"], "role": role, "kind": kind, "family": family or _family(sc), "source_file": src["file"]})
    return out


def _family(sc: dict[str, Any]) -> str:
    if sc.get("id", "").startswith("ART-"):
        return "art:" + sc.get("platform", "?")
    if sc.get("id", "").startswith("LOL-"):
        return "lolbas:" + (sc.get("category") or "?")
    ev = (sc.get("events") or [{}])[0]
    et = str(ev.get("event_type", ""))
    if "adapter" in ev:
        return f"adapter:{ev['adapter']}"
    if et.startswith("web."):
        return "web"
    if et.startswith("process."):
        return "process"
    if et.startswith(("cloud.", "identity.", "email.", "audit.")):
        return "cloud/identity"
    if et.startswith(("network.", "authentication.")):
        return "network/auth"
    return et.split(".")[0] or "other"
