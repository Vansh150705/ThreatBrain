"""Feed the pure correlation engine with recent alerted events from the event store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.logging import get_logger
from app.detection.correlation import GROUP_FIELDS, evaluate_all, load_correlations, rate_event_types
from app.detection.engine import RuleHit
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


def _parse(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=UTC)
    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _shape(row: dict[str, Any]) -> dict[str, Any]:
    dets = row.get("detections") or []
    return {
        "id": row["id"],
        "event_type": row.get("event_type"),
        "at": _parse(row.get("observed_at") or row.get("created_at")),
        "detections": [d["rule_id"] for d in dets if isinstance(d, dict)],
        # one tactic per detection (its primary one): a technique that spans four tactics is still ONE attack phase
        "tactics": [d["tactics"][0] for d in dets if isinstance(d, dict) and d.get("tactics")],
        "techniques": list(row.get("mitre_techniques") or []),
        "tags": [t for d in dets if isinstance(d, dict) for t in d.get("tags", [])],
        "source_ip": row.get("source_ip"),
        "destination_ip": row.get("destination_ip"),
        "username": row.get("username"),
        "asset_name": row.get("asset_name"),
    }


def _claim(org_id: str, event_id: str, hits: list[RuleHit]) -> list[RuleHit]:
    """Keep only the hits this processor is first to record. Another worker that saw the same completion loses
    the INSERT and stays silent, so each completed pattern is reported exactly once."""
    if not hits:
        return []
    rows = [{"organization_id": org_id, "dedupe_key": h.dedupe_key, "correlation_id": h.rule_id, "event_id": event_id} for h in hits]
    won = (
        get_supabase_admin().table("correlation_hits")
        .upsert(rows, on_conflict="organization_id,dedupe_key", ignore_duplicates=True).execute().data or []
    )
    won_keys = {r["dedupe_key"] for r in won}
    return [h for h in hits if h.dedupe_key in won_keys]


def correlate(org_id: str, event_row: dict[str, Any], hits: list[RuleHit]) -> list[RuleHit]:
    """Correlation completions newly visible now that ``event_row`` (already written to the store with its own
    rule detections) exists. Callers MUST persist the event's detections first: with concurrent workers,
    write-then-read is what guarantees that at least one processor of any related pair sees the other."""
    rate_types = rate_event_types()
    if not hits and event_row.get("event_type") not in rate_types:
        return []   # nothing to chain and not a countable event: skip the event-store queries
    current = _shape(event_row)
    if hits:   # the stored row may predate the detections just computed; trust the in-memory hits for this event
        current["detections"] = [h.rule_id for h in hits]
        current["tactics"] = [h.tactics[0] for h in hits if h.tactics]
        current["techniques"] = [t for h in hits for t in h.techniques]
        current["tags"] = [t for h in hits for t in h.tags]
    max_window = max((c.window_minutes for c in load_correlations()), default=60)
    since = (current["at"] - timedelta(minutes=max_window)).isoformat()
    client = get_supabase_admin()
    recent: dict[str, dict[str, Any]] = {}
    types = sorted(rate_types)
    for field in GROUP_FIELDS:
        value = current.get(field)
        if not value:
            continue
        base = client.table("events").select("*").eq("organization_id", org_id).eq(field, str(value)).gte("observed_at", since)
        for rows in (
            base.eq("alerted", True).order("observed_at", desc=True).limit(300).execute().data or [],
            (client.table("events").select("*").eq("organization_id", org_id).eq(field, str(value)).gte("observed_at", since)
             .in_("event_type", types).order("observed_at", desc=True).limit(300).execute().data or []) if types else [],
        ):
            for r in rows:
                if str(r["id"]) != str(event_row["id"]):
                    recent.setdefault(str(r["id"]), _shape(r))
    return _claim(org_id, str(event_row["id"]), evaluate_all(current, list(recent.values())))
