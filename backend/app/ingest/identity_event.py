"""Apply identity canonicalisation to a whole event dict (shared by ingestion and the validation lab)."""

from __future__ import annotations

from typing import Any

from app.ingest.identity import canonical_host, canonical_user


def canonicalize_event(ev: dict[str, Any]) -> dict[str, Any]:
    out = dict(ev)
    if out.get("username"):
        out["username"] = canonical_user(out["username"])
    if out.get("asset_name"):
        out["asset_name"] = canonical_host(out["asset_name"])
    return out
