"""First-run checklist and demo data."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import CurrentUser, require_admin, require_viewer
from app.services import case_service, onboarding_service
from app.services.queue_service import QueueFull  # noqa: F401  (503 handler is app-wide)

router = APIRouter(prefix="/onboarding", tags=["onboarding"])


@router.get("", summary="First-run checklist computed from this organization's real state")
def get_checklist(user: Annotated[CurrentUser, Depends(require_viewer)]) -> dict[str, Any]:
    return onboarding_service.checklist(user.organization_id)


@router.post("/demo", status_code=status.HTTP_202_ACCEPTED, summary="Load a synthetic attack campaign through the real pipeline")
def load_demo(user: Annotated[CurrentUser, Depends(require_admin)]) -> dict[str, Any]:
    try:
        out = onboarding_service.load_demo(user.organization_id)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail={"error": "demo_disabled", "message": str(exc)}) from exc
    case_service.audit(user, action="demo.loaded", target_type="organization", row={"id": user.organization_id, "title": "demo campaign"},
                       changes={"accepted": out["accepted"], "duplicates": out["duplicates"]})
    return out
