"""Durable pipeline runs: synchronous or background execution with a stored trace."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.agents.triage import TriageInput
from app.core.logging import get_logger
from app.services import queue_service
from app.services.orchestrator_service import run_full_pipeline
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

# Runs left "running" for longer than this at startup died with their process.
STALE_AFTER = timedelta(minutes=15)


def shutdown() -> None:
    """Kept for the app lifespan hook; background work now lives in the durable queue/worker."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def create_run(
    organization_id: str, event: TriageInput, *, source: str, created_by: str | None
) -> dict[str, Any]:
    return (
        get_supabase_admin()
        .table("pipeline_runs")
        .insert(
            {
                "organization_id": str(organization_id),
                "status": "queued",
                "source": source,
                "title": event.title[:300],
                "event": event.model_dump(mode="json"),
                "created_by": created_by,
            }
        )
        .execute()
        .data[0]
    )


def execute_run(run_id: str, organization_id: str, event: TriageInput, options: dict[str, Any]) -> dict[str, Any]:
    """Run the pipeline for an existing pipeline_runs row, recording the outcome."""
    client = get_supabase_admin()
    client.table("pipeline_runs").update({"status": "running", "started_at": _now()}).eq(
        "id", run_id
    ).execute()
    try:
        result = run_full_pipeline(organization_id=organization_id, event=event, **options)
    except Exception as exc:
        log.exception("pipeline_run_crashed", run_id=run_id)
        client.table("pipeline_runs").update(
            {
                "status": "failed",
                "completed_at": _now(),
                "error_message": f"{type(exc).__name__}: {str(exc)[:300]}",
            }
        ).eq("id", run_id).execute()
        raise
    failed_all = result["summary"].get("stages_succeeded", 0) == 0
    client.table("pipeline_runs").update(
        {
            "status": "failed" if failed_all else "completed",
            "completed_at": _now(),
            "result": {"stages": result["stages"], "summary": result["summary"]},
            "trace": result["trace"],
        }
    ).eq("id", run_id).execute()
    return result


def run_sync(
    organization_id: str,
    event: TriageInput,
    *,
    source: str,
    created_by: str | None,
    **options: Any,
) -> dict[str, Any]:
    run = create_run(organization_id, event, source=source, created_by=created_by)
    result = execute_run(run["id"], organization_id, event, options)
    result["run_id"] = run["id"]
    return result


def submit_async(
    organization_id: str,
    event: TriageInput,
    *,
    source: str,
    created_by: str | None,
    **options: Any,
) -> dict[str, Any]:
    """Create the run row and enqueue a durable ``pipeline.run`` job; a worker executes it.

    Survives process restarts (the job is in Postgres), is retried on transient failure and
    is applied backpressure (``QueueFull``) rather than spawning unbounded threads.
    """
    queue_service.check_capacity(str(organization_id))
    run = create_run(organization_id, event, source=source, created_by=created_by)
    queue_service.enqueue(
        str(organization_id), "pipeline.run",
        {"run_id": run["id"], "event": event.model_dump(mode="json"), "options": options},
        queue="pipelines", priority=5, max_attempts=3,
    )
    return run


def recover_stale_runs() -> int:
    """At startup, fail runs that were in flight when the previous process died."""
    cutoff = (datetime.now(UTC) - STALE_AFTER).isoformat()
    client = get_supabase_admin()
    stuck = (
        client.table("pipeline_runs")
        .select("id")
        .in_("status", ["queued", "running"])
        .lt("created_at", cutoff)
        .execute()
        .data
        or []
    )
    live: set[str] = set()
    for j in (
        client.table("jobs").select("payload").eq("kind", "pipeline.run").in_("status", ["queued", "running"])
        .limit(5000).execute().data or []
    ):
        if (j.get("payload") or {}).get("run_id"):
            live.add(str(j["payload"]["run_id"]))
    stuck = [r for r in stuck if str(r["id"]) not in live]  # a queued/leased job will still run these
    for row in stuck:
        client.table("pipeline_runs").update(
            {
                "status": "failed",
                "completed_at": _now(),
                "error_message": "Interrupted by a service restart.",
            }
        ).eq("id", row["id"]).execute()
    if stuck:
        log.warning("pipeline_runs_recovered", count=len(stuck))
    return len(stuck)
