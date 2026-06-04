from __future__ import annotations

from typing import Any
from uuid import UUID

from app.services.supabase_client import get_supabase_admin


def get_dashboard_stats(organization_id: UUID) -> dict[str, Any]:
    """Return aggregate counts the dashboard cares about."""
    client = get_supabase_admin()
    org = str(organization_id)

    # Open incidents
    open_incidents = (
        client.table("incidents")
        .select("id", count="exact")
        .eq("organization_id", org)
        .in_("status", ["open", "investigating", "contained"])
        .execute()
    )

    # Total threats
    total_threats = (
        client.table("threats")
        .select("id", count="exact")
        .eq("organization_id", org)
        .execute()
    )

    # Open threats
    open_threats = (
        client.table("threats")
        .select("id", count="exact")
        .eq("organization_id", org)
        .eq("status", "open")
        .execute()
    )

    # Critical threats
    critical_threats = (
        client.table("threats")
        .select("id", count="exact")
        .eq("organization_id", org)
        .eq("severity", "critical")
        .execute()
    )

    return {
        "open_incidents": open_incidents.count or 0,
        "total_threats": total_threats.count or 0,
        "open_threats": open_threats.count or 0,
        "critical_threats": critical_threats.count or 0,
    }