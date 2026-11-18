"""Durable job queue on PostgreSQL (see migration 025: jobs table + claim_jobs()).

Why a database queue: the deployment already depends on Postgres, ``claim_jobs``
uses ``FOR UPDATE SKIP LOCKED`` so any number of workers/replicas can pull safely,
and jobs survive restarts. Delivery is at-least-once: handlers must be idempotent
(the event processor is: it is keyed by the event id and de-duplicates alerts).

Trade-off vs. a broker (Redis/SQS/Kafka): lower throughput ceiling (thousands of
jobs/min on a modest Postgres, not hundreds of thousands) in exchange for zero
extra infrastructure and transactional consistency with the data it processes.
"""

from __future__ import annotations

import random
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class QueueFull(Exception):
    """The queue is above its backpressure ceiling; the caller should retry later."""

    def __init__(self, message: str, retry_after: int = 5) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def _now() -> datetime:
    return datetime.now(UTC)


_depth_cache: dict[str, tuple[float, int]] = {}
_DEPTH_TTL = 2.0


def _queued_count(org_id: str | None) -> int:
    """Queued-job count, cached for a couple of seconds so ingest bursts don't hammer the DB."""
    key = org_id or "*"
    cached = _depth_cache.get(key)
    now = time.monotonic()
    if cached and now - cached[0] < _DEPTH_TTL:
        return cached[1]
    q = get_supabase_admin().table("jobs").select("id", count="exact").eq("status", "queued")
    if org_id:
        q = q.eq("organization_id", org_id)
    n = q.limit(1).execute().count or 0
    _depth_cache[key] = (now, n)
    return n


def reset_depth_cache() -> None:
    _depth_cache.clear()


def check_capacity(org_id: str | None, incoming: int = 1) -> None:
    """Raise QueueFull if accepting ``incoming`` more jobs would breach a ceiling."""
    s = get_settings()
    if _queued_count(None) + incoming > s.QUEUE_MAX_DEPTH:
        raise QueueFull("The ingestion queue is full. Retry shortly.", retry_after=10)
    if org_id and _queued_count(org_id) + incoming > s.QUEUE_MAX_DEPTH_PER_ORG:
        raise QueueFull("Your organization has too many unprocessed events queued. Retry shortly.", retry_after=10)


def enqueue(
    org_id: str | None,
    kind: str,
    payload: dict[str, Any],
    *,
    queue: str = "default",
    priority: int = 5,
    max_attempts: int | None = None,
    delay_seconds: float = 0,
) -> dict[str, Any]:
    row = {
        "organization_id": org_id,
        "queue": queue,
        "kind": kind,
        "payload": payload,
        "priority": priority,
        "max_attempts": max_attempts or get_settings().JOB_MAX_ATTEMPTS,
        "run_after": (_now() + timedelta(seconds=delay_seconds)).isoformat(),
    }
    job = get_supabase_admin().table("jobs").insert(row).execute().data[0]
    _depth_cache.pop("*", None)
    if org_id:
        _depth_cache.pop(org_id, None)
    return job


def enqueue_many(org_id: str, kind: str, payloads: list[dict[str, Any]], **kw: Any) -> list[dict[str, Any]]:
    if not payloads:
        return []
    s = get_settings()
    rows = [
        {
            "organization_id": org_id,
            "queue": kw.get("queue", "default"),
            "kind": kind,
            "payload": p,
            "priority": kw.get("priority", 5),
            "max_attempts": kw.get("max_attempts") or s.JOB_MAX_ATTEMPTS,
        }
        for p in payloads
    ]
    out = get_supabase_admin().table("jobs").insert(rows).execute().data
    _depth_cache.clear()
    return out


def claim(worker_id: str, limit: int, queues: list[str] | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "p_worker": worker_id,
        "p_limit": limit,
        "p_lease_seconds": get_settings().JOB_LEASE_SECONDS,
    }
    if queues:
        params["p_queues"] = queues
    return get_supabase_admin().rpc("claim_jobs", params).execute().data or []


def extend_lease(job_id: str, worker_id: str) -> bool:
    until = (_now() + timedelta(seconds=get_settings().JOB_LEASE_SECONDS)).isoformat()
    rows = (
        get_supabase_admin().table("jobs").update({"locked_until": until})
        .eq("id", job_id).eq("locked_by", worker_id).eq("status", "running").execute().data
    )
    return bool(rows)


def complete(job: dict[str, Any], worker_id: str, result: dict[str, Any] | None = None) -> bool:
    rows = (
        get_supabase_admin().table("jobs")
        .update({"status": "succeeded", "finished_at": _now().isoformat(), "locked_by": None,
                 "locked_until": None, "result": result or {}, "last_error": None})
        .eq("id", job["id"]).eq("locked_by", worker_id).eq("status", "running").execute().data
    )
    return bool(rows)


def backoff_seconds(attempts: int) -> float:
    """Exponential backoff with jitter, capped at 10 minutes."""
    base = get_settings().JOB_RETRY_BASE_SECONDS * (2 ** max(attempts - 1, 0))
    return min(base, 600.0) * random.uniform(0.8, 1.2)  # noqa: S311 (jitter, not security)


def fail(job: dict[str, Any], worker_id: str, error: str, *, retryable: bool = True) -> str:
    """Record a failure. Returns the new status: 'queued' (will retry) or 'dead' (dead-letter)."""
    exhausted = (not retryable) or int(job.get("attempts") or 1) >= int(job.get("max_attempts") or 1)
    patch: dict[str, Any] = {"last_error": error[:1500], "locked_by": None, "locked_until": None}
    if exhausted:
        patch.update(status="dead", finished_at=_now().isoformat())
    else:
        patch.update(status="queued",
                     run_after=(_now() + timedelta(seconds=backoff_seconds(int(job.get("attempts") or 1)))).isoformat())
    get_supabase_admin().table("jobs").update(patch).eq("id", job["id"]).eq("locked_by", worker_id).eq("status", "running").execute()
    return patch["status"]


def requeue_dead(org_id: str, job_id: str) -> dict[str, Any] | None:
    """Operator action: give a dead-lettered job a fresh set of attempts."""
    rows = (
        get_supabase_admin().table("jobs")
        .update({"status": "queued", "attempts": 0, "run_after": _now().isoformat(), "finished_at": None,
                 "last_error": None, "locked_by": None, "locked_until": None})
        .eq("organization_id", org_id).eq("id", job_id).eq("status", "dead").execute().data
    )
    return rows[0] if rows else None


def stats(org_id: str | None = None) -> dict[str, Any]:
    """Queue depth by status, oldest queued age, and recent failures (for dashboards/metrics)."""
    client = get_supabase_admin()
    out: dict[str, Any] = {}
    for status in ("queued", "running", "dead"):
        q = client.table("jobs").select("id", count="exact").eq("status", status)
        if org_id:
            q = q.eq("organization_id", org_id)
        out[status] = q.limit(1).execute().count or 0
    oldest = client.table("jobs").select("created_at").eq("status", "queued")
    if org_id:
        oldest = oldest.eq("organization_id", org_id)
    rows = oldest.order("created_at").limit(1).execute().data or []
    if rows:
        created = datetime.fromisoformat(str(rows[0]["created_at"]).replace("Z", "+00:00"))
        out["oldest_queued_seconds"] = max(0, int((_now() - created).total_seconds()))
    else:
        out["oldest_queued_seconds"] = 0
    return out
