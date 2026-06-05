from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.supabase_client import get_supabase_admin


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
    )

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
        .limit(1)
        .execute()
    )
    rows = response.data or []
    return rows[0] if rows else None


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
        .order("detected_at", desc=True)
        .execute()
    )
    return response.data or []