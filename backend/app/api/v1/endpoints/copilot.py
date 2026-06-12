"""Ask the SOC: a copilot grounded in the caller's own security data.

Builds a compact context window from the org's recent threats, incidents,
and approval queue (all org-scoped), then answers the analyst's question
with the same Groq model the agents use. The model only sees this org's
rows, so tenant isolation holds end to end.
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, get_current_user
from app.core.logging import get_logger
from app.services.llm_service import LLMError, llm_complete
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

router = APIRouter(prefix="/copilot", tags=["copilot"])


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=4000)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    history: list[ChatMessage] = Field(default_factory=list, max_length=10)


class AskResponse(BaseModel):
    answer: str
    model: str
    latency_ms: int


def _gather_context(organization_id: Optional[str]) -> str:
    """Fetch a compact, org-scoped snapshot for grounding."""
    admin = get_supabase_admin()

    threats = (
        admin.table("threats")
        .select(
            "short_id, title, severity, status, confidence, risk_score, "
            "mitre_techniques, source_ips, tags, detected_at"
        )
        .eq("organization_id", organization_id)
        .order("detected_at", desc=True)
        .limit(25)
        .execute()
    ).data or []

    incidents = (
        admin.table("incidents")
        .select(
            "short_id, title, severity, status, priority, risk_score, "
            "threat_count, attribution, tags, first_seen_at, last_seen_at"
        )
        .eq("organization_id", organization_id)
        .order("last_seen_at", desc=True)
        .limit(10)
        .execute()
    ).data or []

    approvals: list[dict[str, Any]] = []
    try:
        approvals = (
            admin.table("playbook_approvals")
            .select("playbook_name, action_type, target, status, incident_short_id")
            .eq("organization_id", organization_id)
            .order("created_at", desc=True)
            .limit(10)
            .execute()
        ).data or []
    except Exception:
        log.warning("copilot_approvals_unavailable")

    return json.dumps(
        {
            "threats": threats,
            "incidents": incidents,
            "playbook_approvals": approvals,
        },
        default=str,
    )


SYSTEM_PROMPT = """You are the ThreatBrain SOC copilot, an assistant for security \
analysts inside a security operations console. You are given a JSON snapshot of the \
analyst's organization: recent threats, incidents, and the playbook approval queue.

Rules:
- Answer ONLY from the snapshot. If the data does not contain the answer, say so \
plainly and suggest where in the console to look (Threats, Incidents, Attack Map, \
Approvals, Audit trail, Run history).
- Be concise and operational. Lead with the answer, then supporting detail.
- Reference items by their short_id (e.g., THR-AC0002, INC-ACT001) so the analyst \
can find them.
- Use plain text or simple markdown lists. No headers, no tables, no code fences.
- Severity order: critical > high > medium > low > info.
- Never invent IPs, IDs, or counts that are not in the snapshot."""


@router.post("/ask", response_model=AskResponse)
async def ask(
    request: AskRequest,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> AskResponse:
    """Answer a natural-language question about the caller's org data."""
    if not user.organization_id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Your account has no organization yet.",
        )

    context = _gather_context(user.organization_id)

    convo = ""
    for msg in request.history[-6:]:
        speaker = "Analyst" if msg.role == "user" else "Copilot"
        convo += f"{speaker}: {msg.content}\n"

    user_prompt = (
        f"ORGANIZATION SNAPSHOT (JSON):\n{context}\n\n"
        + (f"CONVERSATION SO FAR:\n{convo}\n" if convo else "")
        + f"ANALYST QUESTION: {request.question}"
    )

    try:
        result = llm_complete(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
            max_tokens=700,
        )
    except LLMError as exc:
        log.exception("copilot_llm_failed")
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"The copilot model is unavailable right now: {exc}",
        ) from exc

    return AskResponse(
        answer=result.content.strip(),
        model=result.model,
        latency_ms=result.latency_ms,
    )
