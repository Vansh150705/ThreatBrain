from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.supabase_client import get_supabase_admin
from app.services.threat_service import ilike_pattern

VALID_SORT_FIELDS = {
    "created_at",
    "updated_at",
    "first_seen_at",
    "last_seen_at",
    "severity",
    "status",
    "priority",
    "confidence",
    "risk_score",
    "threat_count",
}
VALID_SORT_DIRS = {"asc", "desc"}


def list_incidents(
    organization_id: UUID,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
    search: str | None = None,
    assigned_to: str | None = None,
) -> dict[str, Any]:
    """Fetch paginated incidents for an organization with filters and sorting."""
    client = get_supabase_admin()

    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 25
    if sort_by not in VALID_SORT_FIELDS:
        sort_by = "created_at"
    if sort_dir not in VALID_SORT_DIRS:
        sort_dir = "desc"

    offset = (page - 1) * page_size

    query = (
        client.table("incidents")
        .select("*", count="exact")
        .eq("organization_id", str(organization_id))
        .is_("deleted_at", "null")
    )

    if assigned_to:
        query = query.eq("assigned_to", assigned_to)
    if search and search.strip():
        query = query.ilike("title", ilike_pattern(search))
    if severity:
        query = query.eq("severity", severity)
    if status:
        query = query.eq("status", status)
    if priority:
        query = query.eq("priority", priority)

    query = query.order(sort_by, desc=(sort_dir == "desc"))
    query = query.range(offset, offset + page_size - 1)

    response = query.execute()
    items = response.data or []
    total = response.count or 0

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": (offset + page_size) < total,
    }


def get_incident_detail(organization_id: UUID, incident_id: UUID) -> dict[str, Any] | None:
    """Fetch a single incident by id, scoped to org."""
    client = get_supabase_admin()
    response = (
        client.table("incidents")
        .select("*")
        .eq("organization_id", str(organization_id))
        .eq("id", str(incident_id))
        .is_("deleted_at", "null")
        .limit(1)
        .execute()
    )
    rows = response.data or []
    return rows[0] if rows else None


def get_incident_by_short_id(organization_id: UUID, short_id: str) -> dict[str, Any] | None:
    """Fetch a single incident by its human-friendly short_id (e.g. INC-AC0001)."""
    client = get_supabase_admin()
    response = (
        client.table("incidents")
        .select("*")
        .eq("organization_id", str(organization_id))
        .eq("short_id", short_id)
        .is_("deleted_at", "null")
        .limit(1)
        .execute()
    )
    rows = response.data or []
    return rows[0] if rows else None


def get_incident(organization_id: UUID | str, identifier: str) -> dict[str, Any] | None:
    """Look an incident up by UUID or short_id, scoped to the organization."""
    try:
        return get_incident_detail(organization_id, UUID(identifier))
    except ValueError:
        return get_incident_by_short_id(organization_id, identifier)


def list_threats_for_incident(
    organization_id: UUID,
    incident_id: UUID,
) -> list[dict[str, Any]]:
    """Fetch the threats grouped under an incident."""
    client = get_supabase_admin()
    response = (
        client.table("threats")
        .select("id, short_id, title, severity, status, confidence, mitre_techniques, detected_at, created_at")
        .eq("organization_id", str(organization_id))
        .eq("incident_id", str(incident_id))
        .is_("deleted_at", "null")
        .order("detected_at", desc=True)
        .execute()
    )
    return response.data or []

# ---------------------------------------------------------------------------
# Case construction + correlation helpers (used by the orchestrator/agents)
# ---------------------------------------------------------------------------
from datetime import UTC, datetime, timedelta  # noqa: E402

from app.core.logging import get_logger  # noqa: E402

_log = get_logger(__name__)

SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_PRIORITY_FOR = {"critical": "p1", "high": "p2", "medium": "p3", "low": "p4", "info": "p4"}
_PRIORITY_RANK = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}
ACTIVE_STATUSES = ["open", "investigating", "contained"]


def priority_for_severity(severity: str) -> str:
    return _PRIORITY_FOR.get(severity, "p3")


def _uniq(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(v for v in values if v not in (None, "")))


def refresh_aggregates(organization_id: str, incident_id: str) -> dict[str, Any] | None:
    """Recompute an incident's cached fields from its linked threats.

    Severity/risk come from the worst member, MITRE/IP sets are unions, the
    window spans first->last activity. Priority only ever escalates here, so a
    manual downgrade by an analyst is not silently undone... and a new critical
    threat is never hidden behind a stale P3.
    """
    client = get_supabase_admin()
    org = str(organization_id)
    threats = (
        client.table("threats")
        .select(
            "severity, risk_score, confidence, mitre_tactics, mitre_techniques, source_ips, "
            "affected_users, tags, detected_at, last_seen_at, event_count"
        )
        .eq("organization_id", org)
        .eq("incident_id", str(incident_id))
        .is_("deleted_at", "null")
        .execute()
    ).data or []
    if not threats:
        return None

    incident = (
        client.table("incidents")
        .select("id, priority, severity, first_seen_at")
        .eq("organization_id", org)
        .eq("id", str(incident_id))
        .limit(1)
        .execute()
    ).data
    if not incident:
        return None
    cur = incident[0]

    worst = max((t["severity"] for t in threats), key=lambda s: SEVERITY_RANK.get(s, 0))
    # never lower a severity an analyst/agent already raised on the incident itself
    if SEVERITY_RANK.get(cur.get("severity") or "info", 0) > SEVERITY_RANK.get(worst, 0):
        worst = cur["severity"]
    first = min(str(t["detected_at"]) for t in threats)
    last = max(str(t.get("last_seen_at") or t["detected_at"]) for t in threats)
    derived_priority = priority_for_severity(worst)
    cur_priority = cur.get("priority") or "p3"
    priority = derived_priority if _PRIORITY_RANK[derived_priority] < _PRIORITY_RANK.get(cur_priority, 3) else cur_priority

    update = {
        "threat_count": len(threats),
        "severity": worst,
        "priority": priority,
        "risk_score": max(int(t.get("risk_score") or 0) for t in threats),
        "confidence": round(sum(int(t.get("confidence") or 0) for t in threats) / len(threats)),
        "mitre_tactics": _uniq([x for t in threats for x in (t.get("mitre_tactics") or [])]),
        "mitre_techniques": _uniq([x for t in threats for x in (t.get("mitre_techniques") or [])]),
        "source_ips": _uniq([x for t in threats for x in (t.get("source_ips") or [])]),
        "first_seen_at": min(first, str(cur["first_seen_at"])) if cur.get("first_seen_at") else first,
        "last_seen_at": last,
    }
    # last >= first is a table constraint
    if update["last_seen_at"] < update["first_seen_at"]:
        update["last_seen_at"] = update["first_seen_at"]
    rows = (
        client.table("incidents")
        .update(update)
        .eq("organization_id", org)
        .eq("id", str(incident_id))
        .execute()
    ).data or []
    return rows[0] if rows else None


def create_incident(
    organization_id: str,
    *,
    title: str,
    description: str | None,
    severity: str,
    confidence: int,
    threat_ids: list[str],
    kill_chain: list[str] | None = None,
    attribution: dict[str, Any] | None = None,
    ai_summary: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Create an incident, link ``threat_ids`` to it and fill the cached aggregates."""
    client = get_supabase_admin()
    org = str(organization_id)
    row = (
        client.table("incidents")
        .insert(
            {
                "organization_id": org,
                "title": title[:500],
                "description": description,
                "severity": severity,
                "status": "open",
                "priority": priority_for_severity(severity),
                "confidence": max(0, min(100, int(confidence))),
                "kill_chain": kill_chain or [],
                "attribution": attribution or {},
                "ai_summary": ai_summary or {},
                "tags": tags or [],
                "threat_count": len(threat_ids),
            }
        )
        .execute()
    ).data[0]
    if threat_ids:
        client.table("threats").update({"incident_id": row["id"]}).eq(
            "organization_id", org
        ).in_("id", [str(t) for t in threat_ids]).execute()
    refreshed = refresh_aggregates(org, row["id"])
    return refreshed or row


def find_correlated_incident(
    organization_id: str,
    *,
    source_ips: list[str],
    window_hours: int,
    exclude_incident_id: str | None = None,
) -> dict[str, Any] | None:
    """An active incident that already involves one of the new threat's attacker IPs.

    Deterministic correlation: no model call is needed to know that two alerts
    from the same source against the same environment belong to one story.
    """
    if not source_ips:
        return None
    since = (datetime.now(UTC) - timedelta(hours=window_hours)).isoformat()
    client = get_supabase_admin()
    candidates = (
        client.table("incidents")
        .select("id, short_id, severity, status, source_ips, last_seen_at, title")
        .eq("organization_id", str(organization_id))
        .is_("deleted_at", "null")
        .in_("status", ACTIVE_STATUSES)
        .gte("last_seen_at", since)
        .order("last_seen_at", desc=True)
        .limit(100)
        .execute()
    ).data or []
    wanted_ips = {str(i) for i in source_ips}
    for inc in candidates:
        if exclude_incident_id and inc["id"] == exclude_incident_id:
            continue
        inc_ips = {str(i).split("/")[0] for i in (inc.get("source_ips") or [])}
        if wanted_ips & inc_ips:
            return inc
    return None


def attach_threat(organization_id: str, incident_id: str, threat_id: str) -> dict[str, Any] | None:
    get_supabase_admin().table("threats").update({"incident_id": str(incident_id)}).eq(
        "organization_id", str(organization_id)
    ).eq("id", str(threat_id)).execute()
    return refresh_aggregates(str(organization_id), str(incident_id))
