"""Durable pipeline runs: synchronous or background execution with a stored trace."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from app.agents.triage import TriageInput
from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.orchestrator_service import run_full_pipeline
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

_executor: ThreadPoolExecutor | None = None
_lock = threading.Lock()
# Runs left "running" for longer than this at startup died with their process.
STALE_AFTER = timedelta(minutes=15)


def _get_executor() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=max(1, get_settings().PIPELINE_WORKERS), thread_name_prefix="pipeline"
            )
        return _executor


def shutdown() -> None:
    global _executor
    with _lock:
        if _executor is not None:
            _executor.shutdown(wait=False, cancel_futures=True)
            _executor = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    """Queue a pipeline and return immediately with its run row."""
    run = create_run(organization_id, event, source=source, created_by=created_by)

    def _job() -> None:
        try:
            execute_run(run["id"], organization_id, event, options)
        except Exception:
            pass  # already logged and recorded by execute_run

    _get_executor().submit(_job)
    return run


def recover_stale_runs() -> int:
    """At startup, fail runs that were in flight when the previous process died."""
    cutoff = (datetime.now(timezone.utc) - STALE_AFTER).isoformat()
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
