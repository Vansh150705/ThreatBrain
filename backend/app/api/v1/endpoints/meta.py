from __future__ import annotations

import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from app.api.deps import CurrentUser, get_current_user, require_admin, require_viewer
from app.core.config import get_settings
from app.schemas.organization import OrganizationMini
from app.services import llm_service
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


@router.get("/ready")
def ready(response: Response) -> dict[str, object]:
    """Readiness probe: 503 unless the database answers and the schema is present. Queue/worker problems are
    returned as `warnings` and do not fail the probe (a stalled worker pool must not drop the API from the LB)."""
    from app.services import ops_service

    out = ops_service.readiness()
    if not out["ready"]:
        response.status_code = 503
    # Anonymous callers get the verdict only; details are in /system/status for admins.
    return {"status": "ready" if out["ready"] else "not_ready", "warnings": len(out["warnings"])}


@router.get("/system/status")
def system_status(_: CurrentUser = Depends(require_admin)) -> dict[str, object]:
    from app.services import ops_service

    return ops_service.system_status()


@router.get("/system/jobs", summary="Queue jobs for this organization (admin). Payloads are never returned.")
def list_jobs(
    job_status: Literal["queued", "running", "succeeded", "dead"] = Query(default="dead", alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    user: CurrentUser = Depends(require_admin),
) -> dict[str, object]:
    rows = (
        get_supabase_admin().table("jobs")
        .select("id, kind, status, attempts, max_attempts, last_error, created_at, started_at, finished_at, run_after")
        .eq("organization_id", user.organization_id).eq("status", job_status)
        .order("created_at", desc=True).limit(limit).execute().data or []
    )
    return {"items": rows}


@router.post("/system/jobs/{job_id}/requeue", summary="Give a dead-lettered job a fresh set of attempts (admin)")
def requeue_job(job_id: str, user: CurrentUser = Depends(require_admin)) -> dict[str, object]:
    from app.services import case_service, queue_service

    job = queue_service.requeue_dead(user.organization_id, job_id)
    if job is None:
        raise HTTPException(404, "Job not found or not dead-lettered.")
    case_service.audit(user, action="job.requeued", target_type="job", row={"id": job_id, "title": job["kind"]}, changes={})
    return {"id": job["id"], "status": job["status"]}


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
        llm=llm_service.llm_configured(),
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
    """Returns the authenticated user's resolved identity, including nested org. Humans only."""
    if user.auth_method != "jwt":
        raise HTTPException(403, detail={"error": "insufficient_scope", "message": "API keys cannot use this endpoint."})
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


