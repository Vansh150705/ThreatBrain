from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.agents.base import AgentInput
from app.agents.triage import TriageAgent, TriageInput, TriageOutput
from app.api.deps import CurrentUser, require_analyst
from app.core.logging import get_logger

router = APIRouter()
log = get_logger(__name__)


class TriageClassifyRequest(BaseModel):
    """Body for ``POST /agents/triage/classify``."""

    event: TriageInput
    promote_if_recommended: bool = Field(
        default=True,
        description="If true and the agent recommends promotion, create a threats row.",
    )
    primary_asset_id: str | None = Field(
        default=None,
        description="UUID of the affected asset, for the threats row if promoted.",
    )


class TriageClassifyResponse(BaseModel):
    """Response shape for ``POST /agents/triage/classify``."""

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
    responses={
        401: {"description": "Missing or invalid auth token."},
        403: {"description": "Requires analyst role or higher."},
        422: {"description": "Invalid event payload or LLM produced bad output."},
        503: {"description": "LLM call failed after retries."},
    },
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