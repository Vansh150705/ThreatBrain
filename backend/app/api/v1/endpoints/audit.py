"""Read access to the append-only audit trail.

The audit_logs table is insert-only at the database level (UPDATE and
DELETE are physically rejected by a trigger). This endpoint exposes the
org-scoped view of that trail for the console's Audit page.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import CurrentUser, get_current_user
from app.services.supabase_client import get_supabase_admin

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogItem(BaseModel):
    id: str
    short_id: str
    actor_type: str
    actor_name: Optional[str] = None
    actor_email: Optional[str] = None
    action: str
    target_type: Optional[str] = None
    target_short_id: Optional[str] = None
    target_name: Optional[str] = None
    severity: str
    status: str
    reason: Optional[str] = None
    changes: dict[str, Any] = {}
    created_at: datetime


class AuditListResponse(BaseModel):
    items: list[AuditLogItem]
    total: int


@router.get("", response_model=AuditListResponse)
async def list_audit_logs(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    severity: Optional[str] = Query(default=None),
    actor_type: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditListResponse:
    """Newest-first audit events for the caller's organization."""
    admin = get_supabase_admin()
    query = (
        admin.table("audit_logs")
        .select(
            "id, short_id, actor_type, actor_name, actor_email, action, "
            "target_type, target_short_id, target_name, severity, status, "
            "reason, changes, created_at",
            count="exact",
        )
        .eq("organization_id", user.organization_id)
    )
    if severity:
        query = query.eq("severity", severity)
    if actor_type:
        query = query.eq("actor_type", actor_type)

    result = (
        query.order("created_at", desc=True)
        .range(offset, offset + limit - 1)
        .execute()
    )
    rows = result.data or []
    return AuditListResponse(
        items=[AuditLogItem.model_validate(r) for r in rows],
        total=result.count or 0,
    )
