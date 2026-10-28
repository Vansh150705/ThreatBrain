"""Queue worker: claims jobs from the durable queue and runs them with bounded concurrency.

Runs embedded in the API process (``EMBEDDED_WORKER=true``, single-container mode) or as a
separate process (``python -m app.worker``) that can be scaled horizontally; any number of
workers can run against one database because ``claim_jobs`` uses ``FOR UPDATE SKIP LOCKED``.

Delivery is at-least-once. A handler raising ``PermanentJobError`` goes straight to the
dead-letter state; any other exception is retried with exponential backoff until
``max_attempts`` is used up, then dead-lettered (operators can requeue from the API).
"""

from __future__ import annotations

import os
import socket
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services import queue_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

Handler = Callable[[dict[str, Any]], dict[str, Any] | None]


class PermanentJobError(Exception):
    """Do not retry: the job can never succeed (bad payload, deleted tenant, ...)."""


_HANDLERS: dict[str, Handler] = {}


def register(kind: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        _HANDLERS[kind] = fn
        return fn

    return deco


@register("event.process")
def _handle_event_process(job: dict[str, Any]) -> dict[str, Any]:
    from app.services import event_processor

    p = job.get("payload") or {}
    if not job.get("organization_id") or not p.get("event_id"):
        raise PermanentJobError("event.process needs organization_id and payload.event_id")
    return event_processor.process_event(str(job["organization_id"]), str(p["event_id"]))


@register("pipeline.run")
def _handle_pipeline_run(job: dict[str, Any]) -> dict[str, Any]:
    from app.agents.triage import TriageInput
    from app.services import pipeline_service

    p = job.get("payload") or {}
    if not job.get("organization_id") or not p.get("run_id") or not p.get("event"):
        raise PermanentJobError("pipeline.run needs organization_id, payload.run_id and payload.event")
    existing = get_supabase_admin().table("pipeline_runs").select("status").eq("id", p["run_id"]).limit(1).execute().data
    if existing and existing[0]["status"] in ("completed", "failed"):
        return {"run_id": p["run_id"], "skipped": "already finished (redelivery)"}
    event = TriageInput.model_validate(p["event"])
    result = pipeline_service.execute_run(p["run_id"], str(job["organization_id"]), event, p.get("options") or {})
    return {"run_id": p["run_id"], "summary": result.get("summary", {})}


@register("maintenance.purge")
def _handle_purge(job: dict[str, Any]) -> dict[str, Any]:
    s = get_settings()
    res = get_supabase_admin().rpc("purge_expired", {
        "p_events_days": s.RETENTION_EVENTS_DAYS, "p_evidence_days": s.RETENTION_EVIDENCE_DAYS,
        "p_jobs_days": s.RETENTION_JOBS_DAYS, "p_runs_days": s.RETENTION_RUNS_DAYS,
    }).execute().data
    return {"purged": res}


class Worker:
    def __init__(self, *, role: str = "worker", queues: list[str] | None = None, concurrency: int | None = None) -> None:
        s = get_settings()
        self.worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.role = role
        self.queues = queues
        self.concurrency = max(1, concurrency or s.WORKER_CONCURRENCY)
        self.poll = max(0.05, s.WORKER_POLL_SECONDS)
        self._stop = threading.Event()
        self._pool = ThreadPoolExecutor(max_workers=self.concurrency, thread_name_prefix="job")
        self._inflight = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.stats = {"processed": 0, "failed": 0, "dead": 0, "started_at": datetime.now(UTC).isoformat()}
        self._last_heartbeat = 0.0
        self._last_purge = 0.0

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self.run_forever, name="queue-worker", daemon=True)
        self._thread.start()
        log.info("worker_started", worker_id=self.worker_id, concurrency=self.concurrency)

    def stop(self, timeout: float = 30.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        self._pool.shutdown(wait=True, cancel_futures=False)
        try:
            get_supabase_admin().table("worker_heartbeats").delete().eq("worker_id", self.worker_id).execute()
        except Exception:
            log.warning("worker_heartbeat_cleanup_failed")
        log.info("worker_stopped", worker_id=self.worker_id, **self.stats)

    def run_forever(self) -> None:
        while not self._stop.is_set():
            try:
                did = self.run_once()
            except Exception:
                log.exception("worker_loop_error")
                did = 0
            self._maybe_heartbeat()
            self._maybe_schedule_purge()
            if not did:
                self._stop.wait(self.poll)

    # -- one polling cycle (also used directly by tests) -------------------
    def run_once(self, *, wait: bool = False) -> int:
        with self._lock:
            free = self.concurrency - self._inflight
        if free <= 0:
            return 0
        jobs = queue_service.claim(self.worker_id, free, self.queues)
        futures = []
        for job in jobs:
            with self._lock:
                self._inflight += 1
            futures.append(self._pool.submit(self._execute, job))
        if wait:
            for f in futures:
                f.result()
        return len(jobs)

    def _execute(self, job: dict[str, Any]) -> None:
        t0 = time.perf_counter()
        beat = threading.Event()
        threading.Thread(target=self._lease_keeper, args=(job, beat), daemon=True).start()
        try:
            handler = _HANDLERS.get(job["kind"])
            if handler is None:
                raise PermanentJobError(f"no handler registered for job kind {job['kind']!r}")
            result = handler(job) or {}
            queue_service.complete(job, self.worker_id, result)
            self.stats["processed"] += 1
        except PermanentJobError as exc:
            queue_service.fail(job, self.worker_id, str(exc), retryable=False)
            self.stats["dead"] += 1
            log.warning("job_dead_lettered", job_id=job["id"], kind=job["kind"], error=str(exc))
        except Exception as exc:
            status = queue_service.fail(job, self.worker_id, f"{type(exc).__name__}: {exc}")
            self.stats["failed"] += 1
            self.stats["dead"] += int(status == "dead")
            log.warning("job_failed", job_id=job["id"], kind=job["kind"], attempt=job.get("attempts"),
                        next_status=status, error=f"{type(exc).__name__}: {str(exc)[:200]}")
        finally:
            beat.set()
            with self._lock:
                self._inflight -= 1
            log.info("job_finished", job_id=job["id"], kind=job["kind"], ms=int((time.perf_counter() - t0) * 1000))

    def _lease_keeper(self, job: dict[str, Any], done: threading.Event) -> None:
        interval = max(5.0, get_settings().JOB_LEASE_SECONDS / 3)
        while not done.wait(interval):
            try:
                if not queue_service.extend_lease(job["id"], self.worker_id):
                    return
            except Exception:
                log.warning("lease_extend_failed", job_id=job["id"])

    # -- liveness + housekeeping ------------------------------------------
    def _maybe_heartbeat(self) -> None:
        if time.monotonic() - self._last_heartbeat < 10:
            return
        self._last_heartbeat = time.monotonic()
        try:
            get_supabase_admin().table("worker_heartbeats").upsert({
                "worker_id": self.worker_id, "role": self.role, "version": get_settings().APP_VERSION,
                "last_seen_at": datetime.now(UTC).isoformat(), "stats": {**self.stats, "inflight": self._inflight},
            }, on_conflict="worker_id").execute()
        except Exception:
            log.warning("worker_heartbeat_failed")

    def _maybe_schedule_purge(self) -> None:
        """Every ~6h one worker enqueues a purge job (cheap; duplicates are harmless)."""
        if time.monotonic() - self._last_purge < 6 * 3600:
            return
        self._last_purge = time.monotonic()
        try:
            client = get_supabase_admin()
            recent = client.table("jobs").select("id").eq("kind", "maintenance.purge").in_("status", ["queued", "running"]).limit(1).execute().data
            if not recent:
                queue_service.enqueue(None, "maintenance.purge", {}, queue="maintenance", priority=1, max_attempts=2)
        except Exception:
            log.warning("purge_schedule_failed")


_embedded: Worker | None = None


def start_embedded() -> Worker | None:
    global _embedded
    if _embedded is None and get_settings().EMBEDDED_WORKER:
        _embedded = Worker(role="embedded")
        _embedded.start()
    return _embedded


def stop_embedded() -> None:
    global _embedded
    if _embedded is not None:
        _embedded.stop()
        _embedded = None
