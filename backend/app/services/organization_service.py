from __future__ import annotations

from typing import Any
from uuid import UUID

from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


# Columns we always select for an OrganizationResponse.
# Kept in one place so any future schema change has a single touch point.
_ORG_COLUMNS = (
    "id, name, slug, plan, status, settings, billing_email, "
    "deleted_at, created_at, updated_at"
)


def get_organization_by_id(organization_id: str | UUID) -> dict[str, Any] | None:

    org_id_str = str(organization_id)
    client = get_supabase_admin()

    try:
        result = (
            client.table("organizations")
            .select(_ORG_COLUMNS)
            .eq("id", org_id_str)
            .is_("deleted_at", "null")
            .limit(1)
            .execute()
        )
    except Exception as exc:
        log.exception("organization_query_failed", organization_id=org_id_str)
        raise

    rows = result.data or []
    if not rows:
        log.info("organization_not_found", organization_id=org_id_str)
        return None

    log.debug("organization_loaded", organization_id=org_id_str)
    return rows[0]


def get_organization_by_slug(slug: str) -> dict[str, Any] | None:
    """Fetch a single organization by its URL slug."""
    client = get_supabase_admin()

    try:
        result = (
            client.table("organizations")
            .select(_ORG_COLUMNS)
            .eq("slug", slug)
            .is_("deleted_at", "null")
            .limit(1)
            .execute()
        )
    except Exception:
        log.exception("organization_query_failed", slug=slug)
        raise

    rows = result.data or []
    return rows[0] if rows else None


def update_organization(
    organization_id: str | UUID,
    *,
    updates: dict[str, Any],
) -> dict[str, Any] | None:
    """Patch an organization's mutable fields. Will be wired to an
    endpoint in Phase 4. Returns the updated row or None if not found."""
    if not updates:
        return get_organization_by_id(organization_id)

    org_id_str = str(organization_id)
    client = get_supabase_admin()

    try:
        result = (
            client.table("organizations")
            .update(updates)
            .eq("id", org_id_str)
            .is_("deleted_at", "null")
            .execute()
        )
    except Exception:
        log.exception("organization_update_failed", organization_id=org_id_str)
        raise

    rows = result.data or []
    return rows[0] if rows else None


__all__ = [
    "get_organization_by_id",
    "get_organization_by_slug",
    "update_organization",
]