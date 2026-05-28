from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.config import get_settings
from app.services.supabase_client import supabase_health_check

router = APIRouter(tags=["meta"])


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
    """Deep health check — confirms Supabase connectivity."""
    settings = get_settings()
    db_status = supabase_health_check()
    return {
        "status": "ok" if db_status["ok"] else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": db_status,
        "timestamp_unix": int(time.time()),
    }


@router.get("/me")
async def whoami(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, object]:
    """Returns the authenticated user's resolved identity."""
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "status": user.status,
        "organization_id": user.organization_id,
        "avatar_url": user.avatar_url,
    }


@router.get("/admin-only")
async def admin_only(
    user: CurrentUser = Depends(require_admin),
) -> dict[str, object]:
    """Test endpoint that only admins/owners can reach."""
    return {
        "message": f"Hello {user.full_name or user.email}, you're an admin.",
        "role": user.role,
    }