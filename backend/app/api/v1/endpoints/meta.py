from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.config import get_settings
from app.schemas.organization import OrganizationMini
from app.services.supabase_client import get_supabase_admin, supabase_health_check

router = APIRouter(tags=["meta"])


class MeResponse(BaseModel):
    id: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: str
    status: str
    organization_id: Optional[str] = None
    avatar_url: Optional[str] = None
    organization: Optional[OrganizationMini] = None


@router.get("/health")
async def health() -> dict[str, object]:
    """Liveness probe used by Railway, load balancers, uptime monitors."""
    settings = get_settings()
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "timestamp_unix": int(time.time()),
    }


@router.get("/health/db")
async def health_db() -> dict[str, object]:
    """Deep health check that confirms Supabase connectivity."""
    settings = get_settings()
    db_status = supabase_health_check()
    return {
        "status": "ok" if db_status["ok"] else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": db_status,
        "timestamp_unix": int(time.time()),
    }


@router.get("/me", response_model=MeResponse)
async def whoami(
    user: CurrentUser = Depends(get_current_user),
) -> MeResponse:
    """Returns the authenticated user's resolved identity, including nested org."""
    org: Optional[OrganizationMini] = None
    if user.organization_id:
        admin = get_supabase_admin()
        result = (
            admin.table("organizations")
            .select("id, name, slug, plan")
            .eq("id", user.organization_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if rows:
            org = OrganizationMini.model_validate(rows[0])

    return MeResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        status=user.status,
        organization_id=user.organization_id,
        avatar_url=user.avatar_url,
        organization=org,
    )


@router.get("/admin-only")
async def admin_only(
    user: CurrentUser = Depends(require_admin),
) -> dict[str, object]:
    """Test endpoint that only admins/owners can reach."""
    return {
        "message": f"Hello {user.full_name or user.email}, you're an admin.",
        "role": user.role,
    }