from __future__ import annotations

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.agents.base import AgentInput
from app.agents.investigation import (
    InvestigationAgent,
    InvestigationInput,
    InvestigationOutput,
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
    summary="Classify an event with the Triage Agent",
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
    summary="Enrich an IP IOC with the Threat Intel Agent",
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
    summary="Correlate recent threats into incidents",
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