from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
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

router = APIRouter()
log = get_logger(__name__)

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

class ComplianceAssessRequest(BaseModel):
    incident_short_id: str = Field(..., min_length=3, max_length=40)
    regulations: list[str] | None = Field(
        default=None,
        description="Subset of regulations; default = all common ones.",
    )


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
    summary="Produce regulatory compliance reports for an incident",
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