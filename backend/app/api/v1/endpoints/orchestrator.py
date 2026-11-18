from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.agents.triage import TriageInput
from app.api.deps import CurrentUser, require_analyst, require_viewer
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.ratelimit import rate_limit
from app.services import pipeline_service
from app.services.supabase_client import get_supabase_admin

router = APIRouter()
log = get_logger(__name__)

_llm_limit = rate_limit("llm", per_minute=lambda: get_settings().LLM_RATE_LIMIT_PER_MINUTE)


class OrchestratorRequest(BaseModel):
    event: TriageInput
    primary_asset_id: str | None = None
    promote_threats: bool = Field(default=True)
    run_threat_intel: bool = Field(default=True)
    run_investigation: bool = Field(default=True)
    run_response: bool = Field(default=True)
    run_forensics: bool = Field(default=True)
    run_compliance: bool = Field(default=True)
    investigation_lookback_hours: int = Field(default=72, ge=1, le=720)
    response_mode: Literal["recommend", "simulate"] = Field(
        default="recommend",
        description="recommend: queue validated actions for human approval. "
        "simulate: record what would be proposed, queue nothing.",
    )
    deduplicate: bool = Field(
        default=True, description="Fold repeats of an active threat into it instead of re-running the agents."
    )


class OrchestratorResponse(BaseModel):
    stages: dict[str, Any]
    summary: dict[str, Any]
    trace: list[dict[str, Any]] = Field(default_factory=list)
    run_id: str | None = None


@router.post(
    "/handle-event",
    response_model=OrchestratorResponse,
    status_code=status.HTTP_200_OK,
    summary="Run an event through the full agent pipeline",
    dependencies=[Depends(_llm_limit)],
)
def handle_event(
    request: OrchestratorRequest,
    user: CurrentUser = Depends(require_analyst),
) -> OrchestratorResponse:
    """Run an event through the full agent pipeline and wait for the result.

    Order: detection, triage, threat intel, investigation, then response /
    forensics / compliance in parallel. Each stage is traced in the result.
    """
    result = pipeline_service.run_sync(
        user.organization_id,
        request.event,
        source="manual",
        created_by=user.display_name,
        primary_asset_id=request.primary_asset_id,
        promote_threats=request.promote_threats,
        run_threat_intel=request.run_threat_intel,
        run_investigation=request.run_investigation,
        run_response=request.run_response,
        run_forensics=request.run_forensics,
        run_compliance=request.run_compliance,
        investigation_lookback_hours=request.investigation_lookback_hours,
        response_mode=request.response_mode,
        deduplicate=request.deduplicate,
    )
    return OrchestratorResponse(**result)


class PipelineRunItem(BaseModel):
    id: str
    status: str
    source: str | None = None
    title: str | None = None
    created_by: str | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class PipelineRunDetail(PipelineRunItem):
    event: dict[str, Any] = Field(default_factory=dict)
    stages: dict[str, Any] = Field(default_factory=dict)
    trace: list[dict[str, Any]] = Field(default_factory=list)


class PipelineRunList(BaseModel):
    items: list[PipelineRunItem]
    total: int


_LIST_COLS = "id, status, source, title, created_by, created_at, started_at, completed_at, error_message, result"


def _item(row: dict[str, Any]) -> dict[str, Any]:
    return {**{k: row.get(k) for k in PipelineRunItem.model_fields if k != "summary"},
            "summary": (row.get("result") or {}).get("summary", {})}


@router.get("/runs", response_model=PipelineRunList, summary="Pipeline execution history")
def list_runs(
    user: Annotated[CurrentUser, Depends(require_viewer)],
    run_status: Annotated[str | None, Query(alias="status", pattern="^(queued|running|completed|failed)$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PipelineRunList:
    query = (
        get_supabase_admin()
        .table("pipeline_runs")
        .select(_LIST_COLS, count="exact")
        .eq("organization_id", user.organization_id)
    )
    if run_status:
        query = query.eq("status", run_status)
    res = query.order("created_at", desc=True).range(offset, offset + limit - 1).execute()
    return PipelineRunList(items=[_item(r) for r in res.data or []], total=res.count or 0)


@router.get("/runs/{run_id}", response_model=PipelineRunDetail, summary="One pipeline run with its trace")
def get_run(run_id: str, user: Annotated[CurrentUser, Depends(require_viewer)]) -> PipelineRunDetail:
    rows = (
        get_supabase_admin()
        .table("pipeline_runs")
        .select(_LIST_COLS + ", event, trace")
        .eq("organization_id", user.organization_id)
        .eq("id", run_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pipeline run not found.")
    row = rows[0]
    return PipelineRunDetail(
        **_item(row),
        event=row.get("event") or {},
        stages=(row.get("result") or {}).get("stages", {}),
        trace=row.get("trace") or [],
    )
