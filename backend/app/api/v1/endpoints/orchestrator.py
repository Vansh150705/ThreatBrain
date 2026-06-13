from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.agents.triage import TriageInput
from app.api.deps import CurrentUser, require_analyst
from app.core.logging import get_logger
from app.services.orchestrator_service import run_full_pipeline

router = APIRouter()
log = get_logger(__name__)


# Request / response

class OrchestratorRequest(BaseModel):
    event: TriageInput
    primary_asset_id: str | None = None
    promote_threats: bool = Field(default=True)
    run_threat_intel: bool = Field(default=True)
    run_investigation: bool = Field(default=True)
    run_response: bool = Field(default=True)
    run_forensics: bool = Field(default=True)
    run_compliance: bool = Field(default=True)
    investigation_lookback_hours: int = Field(default=168, ge=1, le=720)


class OrchestratorResponse(BaseModel):
    stages: dict[str, Any]
    summary: dict[str, Any]


# POST /orchestrator/handle-event

@router.post(
    "/handle-event",
    response_model=OrchestratorResponse,
    status_code=status.HTTP_200_OK,
    summary="Run an event through the full agent pipeline",
)
async def handle_event(
    request: OrchestratorRequest,
    user: CurrentUser = Depends(require_analyst),
) -> OrchestratorResponse:
    """Run an event through the full agent pipeline.

    Order is triage, threat intel, investigation, response, forensics, compliance.
    """
    result = run_full_pipeline(
        organization_id=user.organization_id,
        event=request.event,
        primary_asset_id=request.primary_asset_id,
        promote_threats=request.promote_threats,
        run_threat_intel=request.run_threat_intel,
        run_investigation=request.run_investigation,
        run_response=request.run_response,
        run_forensics=request.run_forensics,
        run_compliance=request.run_compliance,
        investigation_lookback_hours=request.investigation_lookback_hours,
    )
    return OrchestratorResponse(**result)