from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.agents.base import AgentInput
from app.agents.compliance import (
    ComplianceAgent,
    ComplianceInput,
    ComplianceOutput,
)
from app.agents.forensics import (
    ForensicsAgent,
    ForensicsInput,
    ForensicsOutput,
)
from app.agents.hunt import HuntAgent, HuntInput, HuntOutput
from app.agents.investigation import (
    InvestigationAgent,
    InvestigationInput,
    InvestigationOutput,
)
from app.agents.response import (
    ResponseAgent,
    ResponseInput,
    ResponseOutput,
)
from app.agents.threat_intel import (
    ThreatIntelAgent,
    ThreatIntelInput,
    ThreatIntelOutput,
)
from app.agents.triage import TriageAgent, TriageInput, TriageOutput
from app.api.deps import CurrentUser, require_analyst
from app.core.logging import get_logger
from app.schemas import (
    AgentListResponse,
    AgentResponse,
    AgentRunDetail,
    AgentRunListResponse,
    AgentRunSummary,
    Pagination,
)
from app.services import agent_service

router = APIRouter()
log = get_logger(__name__)

# Triage
class TriageClassifyRequest(BaseModel):
    event: TriageInput
    promote_if_recommended: bool = Field(default=True)
    primary_asset_id: str | None = None


class TriageClassifyResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: TriageOutput
    model: str
    latency_ms: int
    total_tokens: int
    promoted_threat_id: str | None = None


@router.post(
    "/triage/classify",
    response_model=TriageClassifyResponse,
    status_code=status.HTTP_200_OK,
)
async def triage_classify(
    request: TriageClassifyRequest,
    user: CurrentUser = Depends(require_analyst),
) -> TriageClassifyResponse:
    agent = TriageAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=request.event.model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = TriageOutput.model_validate(run_result.output)

    promoted_id: str | None = None
    if request.promote_if_recommended and verdict.promote_to_threat:
        promoted_id = agent.promote_to_threat(
            organization_id=user.organization_id,
            triage_input=request.event,
            triage_output=verdict,
            agent_run_id=run_result.run_id,
            primary_asset_id=request.primary_asset_id,
        )

    return TriageClassifyResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
        promoted_threat_id=promoted_id,
    )

# Threat Intel
class ThreatIntelEnrichRequest(BaseModel):
    ip_address: str = Field(..., min_length=3, max_length=45)
    context: str | None = Field(default=None, max_length=2000)


class ThreatIntelEnrichResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: ThreatIntelOutput
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/threat-intel/enrich",
    response_model=ThreatIntelEnrichResponse,
    status_code=status.HTTP_200_OK,
)
async def threat_intel_enrich(
    request: ThreatIntelEnrichRequest,
    user: CurrentUser = Depends(require_analyst),
) -> ThreatIntelEnrichResponse:
    agent = ThreatIntelAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=ThreatIntelInput(
            ip_address=request.ip_address,
            context=request.context,
        ).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = ThreatIntelOutput.model_validate(run_result.output)

    return ThreatIntelEnrichResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Investigation
class InvestigationCorrelateRequest(BaseModel):
    lookback_hours: int = Field(default=24, ge=1, le=720)
    max_threats: int = Field(default=30, ge=2, le=100)
    min_severity: str = Field(default="low")
    create_incidents: bool = Field(default=True)


class IncidentSummary(BaseModel):
    incident_id: str
    short_id: str | None = None
    title: str
    threat_count: str


class InvestigationCorrelateResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: InvestigationOutput
    incidents_created: list[IncidentSummary]
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/investigation/correlate",
    response_model=InvestigationCorrelateResponse,
    status_code=status.HTTP_200_OK,
)
async def investigation_correlate(
    request: InvestigationCorrelateRequest,
    user: CurrentUser = Depends(require_analyst),
) -> InvestigationCorrelateResponse:
    agent = InvestigationAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=InvestigationInput(
            lookback_hours=request.lookback_hours,
            max_threats=request.max_threats,
            min_severity=request.min_severity,
        ).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = InvestigationOutput.model_validate(run_result.output)

    incidents_created: list[IncidentSummary] = []
    if request.create_incidents and verdict.groups:
        rows = agent.create_incidents_from_output(
            organization_id=user.organization_id,
            verdict=verdict,
            agent_run_id=run_result.run_id,
        )
        incidents_created = [IncidentSummary(**r) for r in rows]

    return InvestigationCorrelateResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        incidents_created=incidents_created,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Response
class ResponseRecommendRequest(BaseModel):
    incident_short_id: str = Field(..., min_length=3, max_length=40)
    dry_run: bool = Field(default=True)
    execute_auto_playbooks: bool = Field(default=False)


class ResponseRecommendResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: ResponseOutput
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/response/recommend",
    response_model=ResponseRecommendResponse,
    status_code=status.HTTP_200_OK,
)
async def response_recommend(
    request: ResponseRecommendRequest,
    user: CurrentUser = Depends(require_analyst),
) -> ResponseRecommendResponse:
    if (not request.dry_run) and request.execute_auto_playbooks and not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_role",
                "message": "Live playbook execution requires the admin role.",
            },
        )

    agent = ResponseAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=ResponseInput(
            incident_short_id=request.incident_short_id,
            dry_run=request.dry_run,
            execute_auto_playbooks=request.execute_auto_playbooks,
        ).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = ResponseOutput.model_validate(run_result.output)
    verdict = agent.apply_actions(
        organization_id=user.organization_id,
        verdict=verdict,
        agent_run_id=run_result.run_id,
        dry_run=request.dry_run,
        execute_auto_playbooks=request.execute_auto_playbooks,
    )

    return ResponseRecommendResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Forensics
class ForensicsReconstructRequest(BaseModel):
    incident_short_id: str = Field(..., min_length=3, max_length=40)


class ForensicsReconstructResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: ForensicsOutput
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/forensics/reconstruct",
    response_model=ForensicsReconstructResponse,
    status_code=status.HTTP_200_OK,
)
async def forensics_reconstruct(
    request: ForensicsReconstructRequest,
    user: CurrentUser = Depends(require_analyst),
) -> ForensicsReconstructResponse:
    agent = ForensicsAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=ForensicsInput(
            incident_short_id=request.incident_short_id,
        ).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = ForensicsOutput.model_validate(run_result.output)

    return ForensicsReconstructResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Compliance
class ComplianceAssessRequest(BaseModel):
    incident_short_id: str = Field(..., min_length=3, max_length=40)
    regulations: list[str] | None = Field(default=None)


class ComplianceAssessResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: ComplianceOutput
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/compliance/assess",
    response_model=ComplianceAssessResponse,
    status_code=status.HTTP_200_OK,
)
async def compliance_assess(
    request: ComplianceAssessRequest,
    user: CurrentUser = Depends(require_analyst),
) -> ComplianceAssessResponse:
    agent = ComplianceAgent()
    payload_kwargs = {"incident_short_id": request.incident_short_id}
    if request.regulations:
        payload_kwargs["regulations"] = request.regulations

    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=ComplianceInput(**payload_kwargs).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = ComplianceOutput.model_validate(run_result.output)

    return ComplianceAssessResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Hunt
class HuntGenerateRequest(BaseModel):
    lookback_hours: int = Field(default=168, ge=1, le=720)
    focus_areas: list[str] = Field(default_factory=list)
    max_hypotheses: int = Field(default=5, ge=1, le=15)


class HuntGenerateResponse(BaseModel):
    run_id: str
    agent_key: str
    verdict: HuntOutput
    model: str
    latency_ms: int
    total_tokens: int


@router.post(
    "/hunt/generate",
    response_model=HuntGenerateResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate proactive threat hunting hypotheses",
)
async def hunt_generate(
    request: HuntGenerateRequest,
    user: CurrentUser = Depends(require_analyst),
) -> HuntGenerateResponse:
    agent = HuntAgent()
    agent_input = AgentInput(
        organization_id=user.organization_id,
        trigger_type="manual",
        trigger_id=None,
        payload=HuntInput(
            lookback_hours=request.lookback_hours,
            focus_areas=request.focus_areas,
            max_hypotheses=request.max_hypotheses,
        ).model_dump(),
    )
    run_result = agent.run(agent_input)
    verdict = HuntOutput.model_validate(run_result.output)

    return HuntGenerateResponse(
        run_id=run_result.run_id,
        agent_key=run_result.agent_key,
        verdict=verdict,
        model=run_result.model,
        latency_ms=run_result.latency_ms,
        total_tokens=run_result.total_tokens,
    )

# Management endpoints (read-only)
@router.get(
    "",
    response_model=AgentListResponse,
    summary="List all agents for the caller's organization",
)
async def list_agents(
    user: CurrentUser = Depends(require_analyst),
) -> AgentListResponse:
    rows = agent_service.list_agents_for_org(
        organization_id=str(user.organization_id)
    )
    items = [AgentResponse.model_validate(r) for r in rows]
    return AgentListResponse(items=items, total=len(items))


@router.get(
    "/recent-runs",
    response_model=AgentRunListResponse,
    summary="List recent runs across ALL agents",
)
async def list_recent_runs(
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=20, ge=1, le=100),
    run_status: str | None = Query(default=None),
    user: CurrentUser = Depends(require_analyst),
) -> AgentRunListResponse:
    offset = (page - 1) * page_size
    rows, total = agent_service.list_runs(
        organization_id=str(user.organization_id),
        agent_key=None,
        status=run_status,
        limit=page_size,
        offset=offset,
    )
    items = [AgentRunSummary.model_validate(r) for r in rows]
    pagination = Pagination.build(page=page, page_size=page_size, total=total)
    return AgentRunListResponse(items=items, pagination=pagination)


@router.get(
    "/runs/{run_id}",
    response_model=AgentRunDetail,
    summary="Get full details of one specific agent run",
)
async def get_agent_run(
    run_id: str,
    user: CurrentUser = Depends(require_analyst),
) -> AgentRunDetail:
    row = agent_service.get_run_by_id(
        organization_id=str(user.organization_id),
        run_id=run_id,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "run_not_found",
                "message": f"No agent run with id '{run_id}' in your organization.",
            },
        )
    return AgentRunDetail.model_validate(row)


@router.get(
    "/{agent_key}",
    response_model=AgentResponse,
    summary="Get one agent's config and stats",
)
async def get_agent(
    agent_key: str,
    user: CurrentUser = Depends(require_analyst),
) -> AgentResponse:
    row = agent_service.get_agent_by_key(
        organization_id=str(user.organization_id),
        agent_key=agent_key,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "agent_not_found",
                "message": f"No agent with key '{agent_key}' in your organization.",
            },
        )
    return AgentResponse.model_validate(row)


@router.get(
    "/{agent_key}/runs",
    response_model=AgentRunListResponse,
    summary="List recent runs for a specific agent",
)
async def list_agent_runs(
    agent_key: str,
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=20, ge=1, le=100),
    run_status: str | None = Query(default=None),
    user: CurrentUser = Depends(require_analyst),
) -> AgentRunListResponse:
    offset = (page - 1) * page_size
    rows, total = agent_service.list_runs(
        organization_id=str(user.organization_id),
        agent_key=agent_key,
        status=run_status,
        limit=page_size,
        offset=offset,
    )
    items = [AgentRunSummary.model_validate(r) for r in rows]
    pagination = Pagination.build(page=page, page_size=page_size, total=total)
    return AgentRunListResponse(items=items, pagination=pagination)