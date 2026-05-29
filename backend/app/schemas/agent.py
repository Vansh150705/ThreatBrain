from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import Pagination


# Agent

class AgentResponse(BaseModel):
    """One agent's config + stats."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_key: str
    name: str
    description: str | None = None
    status: str
    enabled: bool
    model: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    system_prompt: str | None = None

    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    avg_latency_ms: int | None = None
    last_run_at: datetime | None = None

    created_at: datetime
    updated_at: datetime


class AgentListResponse(BaseModel):
    """List of agents for an org."""

    items: list[AgentResponse]
    total: int

# Agent run

class AgentRunSummary(BaseModel):
    """Compact summary for list views — no full input/output."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    agent_key: str
    trigger_type: str
    trigger_id: UUID | None = None
    status: str
    error_message: str | None = None
    model: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime


class AgentRunDetail(AgentRunSummary):
    """Full run details including input/output/reasoning."""

    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    reasoning: str | None = None


class AgentRunListResponse(BaseModel):
    """Paginated list of runs."""

    items: list[AgentRunSummary]
    pagination: Pagination


__all__ = [
    "AgentResponse",
    "AgentListResponse",
    "AgentRunSummary",
    "AgentRunDetail",
    "AgentRunListResponse",
]