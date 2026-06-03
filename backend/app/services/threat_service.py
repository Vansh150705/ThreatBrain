from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.supabase_client import get_supabase_admin


VALID_SORT_FIELDS = {"created_at", "detected_at", "severity", "status", "confidence", "risk_score"}
VALID_SORT_DIRS = {"asc", "desc"}


def list_threats(
    organization_id: UUID,
    page: int = 1,
    page_size: int = 25,
    severity: str | None = None,
    status: str | None = None,
    sort_by: str = "created_at",
    sort_dir: str = "desc",
) -> dict[str, Any]:
    """Fetch paginated threats for an organization with filters and sorting."""
    client = get_supabase_admin()

    # Validation
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 25
    if sort_by not in VALID_SORT_FIELDS:
        sort_by = "created_at"
    if sort_dir not in VALID_SORT_DIRS:
        sort_dir = "desc"

    offset = (page - 1) * page_size

    # Base query with count
    query = (
        client.table("threats")
        .select("*", count="exact")
        .eq("organization_id", str(organization_id))
    )

    # Apply filters
    if severity:
        query = query.eq("severity", severity)
    if status:
        query = query.eq("status", status)

    # Sort and paginate
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


def get_threat_detail(organization_id: UUID, threat_id: UUID) -> dict[str, Any] | None:
    """Fetch a single threat by id, scoped to org."""
    client = get_supabase_admin()
    response = (
        client.table("threats")
        .select("*")
        .eq("organization_id", str(organization_id))
        .eq("id", str(threat_id))
        .limit(1)
        .execute()
    )
    rows = response.data or []
    return rows[0] if rows else None


def get_threat_by_short_id(organization_id: UUID, short_id: str) -> dict[str, Any] | None:
    """Fetch a single threat by its human-friendly short_id (e.g. THR-A1B2)."""
    client = get_supabase_admin()
    response = (
        client.table("threats")
        .select("*")
        .eq("organization_id", str(organization_id))
        .eq("short_id", short_id)
        .limit(1)
        .execute()
    )
    rows = response.data or []
    return rows[0] if rows else None