"""Universal ingestion front door for external collectors (tb-collector, SDKs, webhooks)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.agents.triage import TriageInput
from app.api.deps import CurrentUser, require_analyst
from app.core.logging import get_logger
from app.services.orchestrator_service import run_full_pipeline

router = APIRouter(prefix="/ingest", tags=["ingest"])
log = get_logger(__name__)


class IngestEventRequest(BaseModel):
    event: TriageInput
    source_system: str | None = Field(
        default=None,
        description="Name of the sending collector/source, e.g. 'tb-collector/auth.log'.",
    )
    collector_id: str | None = Field(
        default=None,
        description="Stable identifier of the collector instance that sent this.",
    )


class IngestEventResponse(BaseModel):
    stages: dict[str, Any]
    summary: dict[str, Any]


@router.post(
    "/event",
    response_model=IngestEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest one real security event and run the full agent pipeline",
)
async def ingest_event(
    request: IngestEventRequest,
    user: CurrentUser = Depends(require_analyst),
) -> IngestEventResponse:
    """Accept a normalized event from an external collector and run the pipeline."""
    log.info(
        "ingest_event_received",
        source_system=request.source_system,
        collector_id=request.collector_id,
        source_ip=request.event.source_ip,
        event_type=request.event.event_type,
    )
    result = run_full_pipeline(
        organization_id=user.organization_id,
        event=request.event,
    )
    return IngestEventResponse(**result)
