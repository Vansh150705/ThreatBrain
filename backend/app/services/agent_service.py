from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

_AGENT_COLUMNS = (
    "id, agent_key, name, description, status, enabled, "
    "model, temperature, max_tokens, system_prompt, "
    "total_runs, successful_runs, failed_runs, avg_latency_ms, "
    "last_run_at, created_at, updated_at"
)

_RUN_COLUMNS = (
    "id, organization_id, agent_id, agent_key, "
    "trigger_type, trigger_id, status, error_message, "
    "model, prompt_tokens, completion_tokens, total_tokens, "
    "latency_ms, started_at, completed_at, created_at, "
    "input, output, reasoning"
)

# Agents

def list_agents_for_org(*, organization_id: str) -> list[dict[str, Any]]:
    """Return all agents for an organization, ordered by agent_key."""
    client = get_supabase_admin()
    result = (
        client.table("agents")
        .select(_AGENT_COLUMNS)
        .eq("organization_id", organization_id)
        .order("agent_key", desc=False)
        .execute()
    )
    return result.data or []


def get_agent_by_key(
    *, organization_id: str, agent_key: str
) -> dict[str, Any] | None:
    """Return a specific agent's full config + stats."""
    client = get_supabase_admin()
    result = (
        client.table("agents")
        .select(_AGENT_COLUMNS)
        .eq("organization_id", organization_id)
        .eq("agent_key", agent_key)
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None

# Agent runs

def list_runs(
    *,
    organization_id: str,
    agent_key: str | None = None,
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """List recent agent runs with filtering. Returns (rows, total_count)."""
    client = get_supabase_admin()
    query = (
        client.table("agent_runs")
        .select(_RUN_COLUMNS, count="exact")
        .eq("organization_id", organization_id)
    )
    if agent_key:
        query = query.eq("agent_key", agent_key)
    if status:
        query = query.eq("status", status)

    result = (
        query.order("created_at", desc=True)
        .range(offset, offset + limit - 1)
        .execute()
    )
    return result.data or [], (result.count or 0)


def get_run_by_id(
    *, organization_id: str, run_id: str
) -> dict[str, Any] | None:
    """Return a single agent_run by its UUID with full input/output."""
    client = get_supabase_admin()
    result = (
        client.table("agent_runs")
        .select(_RUN_COLUMNS)
        .eq("organization_id", organization_id)
        .eq("id", run_id)
        .limit(1)
        .execute()
    )
    rows = result.data or []
    return rows[0] if rows else None


__all__ = [
    "list_agents_for_org",
    "get_agent_by_key",
    "list_runs",
    "get_run_by_id",
]