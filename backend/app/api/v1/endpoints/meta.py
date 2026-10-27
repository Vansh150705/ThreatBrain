from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.api.deps import CurrentUser, get_current_user, require_viewer
from app.core.config import get_settings
from app.schemas.organization import OrganizationMini
from app.services.supabase_client import get_supabase_admin, supabase_health_check

router = APIRouter(tags=["meta"])


class MeResponse(BaseModel):
    id: str
    email: Optional[str] = None
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
def health_db(response: Response) -> dict[str, object]:
    """Deep health check that confirms Supabase connectivity (readiness probe)."""
    settings = get_settings()
    db_status = supabase_health_check()
    if not db_status["ok"]:
        response.status_code = 503
    return {
        "status": "ok" if db_status["ok"] else "degraded",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        # never expose the underlying driver error to anonymous callers
        "database": {"ok": bool(db_status["ok"])},
        "timestamp_unix": int(time.time()),
    }


class IntegrationStatus(BaseModel):
    llm: bool
    abuseipdb: bool
    virustotal: bool
    otx: bool
    discord_notifications: bool
    public_signup: bool
    hunt_scheduler: bool
    rate_limiting: bool


@router.get("/system/integrations", response_model=IntegrationStatus)
def integrations(_: CurrentUser = Depends(require_viewer)) -> IntegrationStatus:
    """Which optional integrations are configured (never returns the secrets)."""
    s = get_settings()
    return IntegrationStatus(
        llm=bool(s.GROQ_API_KEY),
        abuseipdb=bool(s.ABUSEIPDB_API_KEY),
        virustotal=bool(s.VIRUSTOTAL_API_KEY),
        otx=bool(s.OTX_API_KEY),
        discord_notifications=s.discord_webhook_ok,
        public_signup=s.ALLOW_PUBLIC_SIGNUP,
        hunt_scheduler=s.HUNT_INTERVAL_MINUTES > 0,
        rate_limiting=s.RATE_LIMIT_ENABLED,
    )


@router.get("/me", response_model=MeResponse)
def whoami(
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


