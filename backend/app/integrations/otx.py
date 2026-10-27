"""AlienVault OTX IPv4 reputation lookup."""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations._http import FeedNotConfigured, get_json

log = get_logger(__name__)


def check_ip(ip: str) -> dict[str, Any]:
    """Return a normalised summary: pulse count, reputation, country, ASN."""
    s = get_settings()
    if not s.OTX_API_KEY:
        raise FeedNotConfigured("OTX_API_KEY is not configured.")
    body = get_json(
        f"{str(s.OTX_BASE_URL).rstrip('/')}/indicators/IPv4/{ip}/general",
        headers={"X-OTX-API-KEY": s.OTX_API_KEY, "Accept": "application/json"},
        feed="otx",
    )
    pulses = (body.get("pulse_info") or {}).get("pulses") or []
    count = int((body.get("pulse_info") or {}).get("count") or 0)
    out = {
        "pulse_count": count,
        "reputation": body.get("reputation"),
        "country_code": body.get("country_code"),
        "country_name": body.get("country_name"),
        "asn": body.get("asn"),
        "pulse_names": [str(p.get("name"))[:80] for p in pulses[:5] if isinstance(p, dict)],
        "tags": sorted({t for p in pulses[:10] if isinstance(p, dict) for t in (p.get("tags") or [])})[:10],
    }
    log.info("otx_check_completed", ip=ip, pulse_count=count)
    return out


def score(data: dict[str, Any]) -> int:
    """0-100 threat score from OTX pulse volume."""
    return min(100, int(data.get("pulse_count") or 0) * 10)
