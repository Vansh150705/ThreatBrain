"""Threat-intel aggregation across every configured feed."""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.detection.iocs import is_public_ip
from app.integrations import abuseipdb, otx, virustotal
from app.integrations._http import FeedError

log = get_logger(__name__)


def configured_feeds() -> list[str]:
    s = get_settings()
    feeds = []
    if s.ABUSEIPDB_API_KEY:
        feeds.append("abuseipdb")
    if s.VIRUSTOTAL_API_KEY:
        feeds.append("virustotal")
    if s.OTX_API_KEY:
        feeds.append("otx")
    return feeds


def enrich_ip(ip: str) -> dict[str, Any]:
    """Query every configured feed for ``ip``.

    Returns ``{"internal": bool, "feeds": {name: data}, "errors": {name: msg},
    "scores": {name: 0-100}, "composite_score": int | None}``. One failing feed
    never fails the lookup; the errors are reported so analysts can see which
    sources contributed. Non-public addresses are never sent to third parties.
    """
    if not is_public_ip(ip):
        return {"internal": True, "feeds": {}, "errors": {}, "scores": {}, "composite_score": None}

    feeds: dict[str, Any] = {}
    errors: dict[str, str] = {}
    scores: dict[str, int] = {}

    lookups = (
        ("abuseipdb", lambda: abuseipdb.check_ip(ip, max_age_days=90, verbose=True),
         lambda d: int(d.get("abuseConfidenceScore") or 0)),
        ("virustotal", lambda: virustotal.check_ip(ip), virustotal.score),
        ("otx", lambda: otx.check_ip(ip), otx.score),
    )
    for name, fetch, scorer in lookups:
        try:
            data = fetch()
        except (FeedError, abuseipdb.AbuseIPDBError) as exc:
            if "not configured" in str(exc).lower():
                continue
            errors[name] = str(exc)[:200]
            log.warning("intel_feed_failed", feed=name, ip=ip, error=str(exc)[:200])
            continue
        feeds[name] = data
        scores[name] = scorer(data)

    composite: int | None = None
    if scores:
        vals = list(scores.values())
        # The loudest feed dominates, the average tempers one-feed outliers.
        composite = round(max(vals) * 0.7 + (sum(vals) / len(vals)) * 0.3)
    return {"internal": False, "feeds": feeds, "errors": errors, "scores": scores, "composite_score": composite}
