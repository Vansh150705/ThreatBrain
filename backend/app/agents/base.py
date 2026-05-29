from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.core.logging import get_logger
from app.services.llm_service import LLMError, LLMResult, llm_complete, llm_json
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class AgentInput(BaseModel):

    organization_id: UUID
    trigger_type: str = Field(
        ...,
        description="event | threat | incident | manual | scheduled | webhook | chained",
    )
    trigger_id: UUID | None = Field(
        default=None, description="UUID of the triggering entity, if any."
    )
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Freeform context the agent should reason about.",
    )


class AgentRunResult(BaseModel):

    agent_key: str
    agent_id: str
    run_id: str
    status: str = "completed"
    output: dict[str, Any]
    reasoning: str | None = None
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int


class AgentConfigError(Exception):
    """Raised when an agent's row is missing or misconfigured."""

class BaseAgent(ABC):


    agent_key: str = ""
    json_mode: bool = True

    def __init__(self) -> None:
        if not self.agent_key:
            raise AgentConfigError(
                f"{type(self).__name__} must set `agent_key`."
            )
        
    def run(self, agent_input: AgentInput) -> AgentRunResult:

        run_start = time.perf_counter()

        # 1. Load agent config
        agent_row = self._load_agent_row(agent_input.organization_id)

        # 2. Build prompt
        try:
            user_prompt = self.build_user_prompt(agent_input)
        except Exception as exc:
            log.exception(
                "agent_prompt_build_failed",
                agent_key=self.agent_key,
                organization_id=str(agent_input.organization_id),
            )
            run_id = self._record_failed_run(
                agent_row=agent_row,
                agent_input=agent_input,
                error=f"Prompt build failed: {exc}",
                latency_ms=int((time.perf_counter() - run_start) * 1000),
            )
            raise

        log.info(
            "agent_run_starting",
            agent_key=self.agent_key,
            agent_id=agent_row["id"],
            trigger_type=agent_input.trigger_type,
            trigger_id=str(agent_input.trigger_id) if agent_input.trigger_id else None,
        )

        # 3. Call the LLM
        try:
            if self.json_mode:
                parsed_output, llm_result = llm_json(
                    system_prompt=agent_row["system_prompt"] or self._default_system_prompt(),
                    user_prompt=user_prompt,
                    model=agent_row.get("model"),
                    temperature=float(agent_row.get("temperature") or 0.2),
                    max_tokens=int(agent_row.get("max_tokens") or 4096),
                )
                reasoning = self.extract_reasoning(parsed_output)
            else:
                llm_result = llm_complete(
                    system_prompt=agent_row["system_prompt"] or self._default_system_prompt(),
                    user_prompt=user_prompt,
                    model=agent_row.get("model"),
                    temperature=float(agent_row.get("temperature") or 0.2),
                    max_tokens=int(agent_row.get("max_tokens") or 4096),
                )
                parsed_output = {"content": llm_result.content}
                reasoning = llm_result.content
        except LLMError as exc:
            log.exception(
                "agent_llm_call_failed",
                agent_key=self.agent_key,
                agent_id=agent_row["id"],
            )
            self._record_failed_run(
                agent_row=agent_row,
                agent_input=agent_input,
                error=str(exc),
                latency_ms=int((time.perf_counter() - run_start) * 1000),
            )
            raise

        # 4. Validate
        try:
            self.validate_output(parsed_output)
        except Exception as exc:
            log.exception(
                "agent_output_validation_failed",
                agent_key=self.agent_key,
                agent_id=agent_row["id"],
            )
            self._record_failed_run(
                agent_row=agent_row,
                agent_input=agent_input,
                error=f"Output validation failed: {exc}",
                latency_ms=int((time.perf_counter() - run_start) * 1000),
                output=parsed_output,
            )
            raise

        # 5. Persist a successful agent_runs row
        total_latency_ms = int((time.perf_counter() - run_start) * 1000)
        run_id = self._record_successful_run(
            agent_row=agent_row,
            agent_input=agent_input,
            user_prompt=user_prompt,
            output=parsed_output,
            reasoning=reasoning,
            llm_result=llm_result,
            latency_ms=total_latency_ms,
        )

        log.info(
            "agent_run_completed",
            agent_key=self.agent_key,
            agent_id=agent_row["id"],
            run_id=run_id,
            latency_ms=total_latency_ms,
            total_tokens=llm_result.total_tokens,
        )

        # 6. Return
        return AgentRunResult(
            agent_key=self.agent_key,
            agent_id=agent_row["id"],
            run_id=run_id,
            status="completed",
            output=parsed_output,
            reasoning=reasoning,
            model=llm_result.model,
            prompt_tokens=llm_result.prompt_tokens,
            completion_tokens=llm_result.completion_tokens,
            total_tokens=llm_result.total_tokens,
            latency_ms=total_latency_ms,
        )

    @abstractmethod
    def build_user_prompt(self, agent_input: AgentInput) -> str:
        """Construct the LLM user message from `agent_input`."""

    def validate_output(self, parsed: dict[str, Any]) -> None:
        """Subclasses may raise to reject bad LLM output."""
        return None

    def extract_reasoning(self, parsed: dict[str, Any]) -> str | None:
        """Pull a 'reasoning' string from the parsed JSON (for display)."""
        for key in ("reasoning", "explanation", "rationale", "analysis"):
            if isinstance(parsed.get(key), str):
                return parsed[key]
        return None

    def _default_system_prompt(self) -> str:
        return (
            f"You are the {self.agent_key} agent in ThreatBrain, an AI-powered SOC. "
            "Respond precisely and concisely."
        )

    def _load_agent_row(self, organization_id: UUID | str) -> dict[str, Any]:
        """Fetch the agent's config row for this org."""
        client = get_supabase_admin()
        result = (
            client.table("agents")
            .select("id, agent_key, name, model, temperature, max_tokens, system_prompt, config, status, enabled")
            .eq("organization_id", str(organization_id))
            .eq("agent_key", self.agent_key)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if not rows:
            raise AgentConfigError(
                f"No {self.agent_key} agent configured for org {organization_id}."
            )
        row = rows[0]
        if not row.get("enabled"):
            raise AgentConfigError(
                f"{self.agent_key} agent is disabled for org {organization_id}."
            )
        return row

    def _record_successful_run(
        self,
        *,
        agent_row: dict[str, Any],
        agent_input: AgentInput,
        user_prompt: str,
        output: dict[str, Any],
        reasoning: str | None,
        llm_result: LLMResult,
        latency_ms: int,
    ) -> str:
        """Insert a completed agent_runs row and return its UUID."""
        client = get_supabase_admin()
        result = (
            client.table("agent_runs")
            .insert(
                {
                    "organization_id": str(agent_input.organization_id),
                    "agent_id": agent_row["id"],
                    "agent_key": self.agent_key,
                    "trigger_type": agent_input.trigger_type,
                    "trigger_id": str(agent_input.trigger_id)
                    if agent_input.trigger_id
                    else None,
                    "input": {
                        "payload": agent_input.payload,
                        "user_prompt": user_prompt[:8000],
                    },
                    "output": output,
                    "reasoning": reasoning,
                    "status": "completed",
                    "model": llm_result.model,
                    "prompt_tokens": llm_result.prompt_tokens,
                    "completion_tokens": llm_result.completion_tokens,
                    "total_tokens": llm_result.total_tokens,
                    "latency_ms": latency_ms,
                    "started_at": "now()",
                    "completed_at": "now()",
                }
            )
            .execute()
        )
        return result.data[0]["id"]

    def _record_failed_run(
        self,
        *,
        agent_row: dict[str, Any],
        agent_input: AgentInput,
        error: str,
        latency_ms: int,
        output: dict[str, Any] | None = None,
    ) -> str:
        """Insert a failed agent_runs row and return its UUID."""
        client = get_supabase_admin()
        result = (
            client.table("agent_runs")
            .insert(
                {
                    "organization_id": str(agent_input.organization_id),
                    "agent_id": agent_row["id"],
                    "agent_key": self.agent_key,
                    "trigger_type": agent_input.trigger_type,
                    "trigger_id": str(agent_input.trigger_id)
                    if agent_input.trigger_id
                    else None,
                    "input": {"payload": agent_input.payload},
                    "output": output or {},
                    "status": "failed",
                    "error_message": error[:2000],
                    "latency_ms": latency_ms,
                    "started_at": "now()",
                    "completed_at": "now()",
                }
            )
            .execute()
        )
        return result.data[0]["id"]


__all__ = [
    "BaseAgent",
    "AgentInput",
    "AgentRunResult",
    "AgentConfigError",
]