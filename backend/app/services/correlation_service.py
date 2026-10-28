"""Feed the pure correlation engine with recent alerted events from the event store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.logging import get_logger
from app.detection.correlation import GROUP_FIELDS, evaluate_all, load_correlations
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
        "at": _parse(row.get("observed_at") or row.get("created_at")),
        "detections": [d["rule_id"] for d in dets if isinstance(d, dict)],
        "tactics": list(row.get("mitre_tactics") or []),
        "techniques": list(row.get("mitre_techniques") or []),
        "tags": [t for d in dets if isinstance(d, dict) for t in d.get("tags", [])],
        "source_ip": row.get("source_ip"),
        "destination_ip": row.get("destination_ip"),
        "username": row.get("username"),
        "asset_name": row.get("asset_name"),
    }


def correlate(org_id: str, event_row: dict[str, Any], hits: list[RuleHit]) -> list[RuleHit]:
    """Correlations completed by ``event_row`` (whose own rule ``hits`` are already known)."""
    if not hits:
        return []
    current = _shape({**event_row, "detections": [h.as_dict() for h in hits],
                      "mitre_tactics": [t for h in hits for t in h.tactics],
                      "mitre_techniques": [t for h in hits for t in h.techniques]})
    max_window = max((c.window_minutes for c in load_correlations()), default=60)
    since = (current["at"] - timedelta(minutes=max_window)).isoformat()
    client = get_supabase_admin()
    recent: list[dict[str, Any]] = []
    seen: set[str] = set()
    for field in GROUP_FIELDS:
        value = current.get(field)
        if not value:
            continue
        rows = (
            client.table("events").select("*").eq("organization_id", org_id).eq(field, str(value))
            .eq("alerted", True).gte("observed_at", since).order("observed_at", desc=True).limit(300)
            .execute().data or []
        )
        for r in rows:
            if str(r["id"]) not in seen and str(r["id"]) != str(event_row["id"]):
                seen.add(str(r["id"]))
                recent.append(_shape(r))
    return evaluate_all(current, recent)
