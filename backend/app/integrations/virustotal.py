"""VirusTotal v3 lookups (IP addresses and file hashes)."""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations._http import FeedNotConfigured, get_json

log = get_logger(__name__)


def _headers() -> dict[str, str]:
    s = get_settings()
    if not s.VIRUSTOTAL_API_KEY:
        raise FeedNotConfigured("VIRUSTOTAL_API_KEY is not configured.")
    return {"x-apikey": s.VIRUSTOTAL_API_KEY, "Accept": "application/json"}


def _stats(body: dict[str, Any]) -> dict[str, Any]:
    attrs = (body.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious") or 0),
        "suspicious": int(stats.get("suspicious") or 0),
        "harmless": int(stats.get("harmless") or 0),
        "undetected": int(stats.get("undetected") or 0),
        "reputation": attrs.get("reputation"),
        "country_code": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
    }


def check_ip(ip: str) -> dict[str, Any]:
    base = str(get_settings().VIRUSTOTAL_BASE_URL).rstrip("/")
    out = _stats(get_json(f"{base}/ip_addresses/{ip}", headers=_headers(), feed="virustotal"))
    log.info("virustotal_ip_completed", ip=ip, malicious=out["malicious"])
    return out


def check_hash(file_hash: str) -> dict[str, Any]:
    base = str(get_settings().VIRUSTOTAL_BASE_URL).rstrip("/")
    out = _stats(get_json(f"{base}/files/{file_hash}", headers=_headers(), feed="virustotal"))
    log.info("virustotal_hash_completed", malicious=out["malicious"])
    return out


def score(data: dict[str, Any]) -> int:
    """0-100: each malicious engine is strong evidence, each suspicious weaker."""
    return min(100, int(data.get("malicious") or 0) * 12 + int(data.get("suspicious") or 0) * 5)
