"""Operational introspection: readiness checks, system status, config doctor. No secrets are ever returned."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services import queue_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

# The schema level this build of the API needs. Bump when a new migration is required by code.
REQUIRED_MIGRATION = "026_correlation_ledger.sql"
REQUIRED_TABLES = ("jobs", "events", "threat_events", "detection_rules", "rule_overrides", "replay_guard", "worker_heartbeats", "correlation_hits")
WORKER_STALE_SECONDS = 60
QUEUE_STUCK_SECONDS = 300


def check_database() -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        get_supabase_admin().table("organizations").select("id").limit(1).execute()
        return {"ok": True, "latency_ms": int((time.perf_counter() - t0) * 1000)}
    except Exception as exc:
        log.warning("readiness_db_failed", error=type(exc).__name__)
        return {"ok": False, "error": type(exc).__name__}


def check_schema() -> dict[str, Any]:
    """The required migration is recorded in the ledger, or (for hand-applied databases) its tables answer."""
    client = get_supabase_admin()
    ledger: bool | None = None
    try:
        rows = client.table("schema_migrations").select("filename").eq("filename", REQUIRED_MIGRATION).limit(1).execute().data
        ledger = bool(rows)
    except Exception:
        ledger = None  # ledger table missing: database was not migrated with migrate.sh
    missing = []
    for t in REQUIRED_TABLES:
        try:
            client.table(t).select("*").limit(1).execute()
        except Exception:
            missing.append(t)
    return {"ok": not missing, "required": REQUIRED_MIGRATION, "ledger_has_required": ledger, "missing_tables": missing}


def check_workers() -> dict[str, Any]:
    s = get_settings()
    try:
        rows = get_supabase_admin().table("worker_heartbeats").select("worker_id, role, last_seen_at, stats").execute().data or []
    except Exception:
        return {"ok": False, "error": "heartbeat table unreadable"}
    now = datetime.now(UTC)
    live = []
    for r in rows:
        try:
            seen = datetime.fromisoformat(str(r["last_seen_at"]).replace("Z", "+00:00"))
            if seen.tzinfo is None:
                seen = seen.replace(tzinfo=UTC)
            if (now - seen).total_seconds() <= WORKER_STALE_SECONDS:
                live.append({"worker_id": r["worker_id"], "role": r["role"], "age_seconds": int((now - seen).total_seconds())})
        except (ValueError, KeyError):
            continue
    return {"ok": bool(live) or s.EMBEDDED_WORKER, "live": len(live), "workers": live, "embedded": s.EMBEDDED_WORKER}


def check_queue() -> dict[str, Any]:
    try:
        st = queue_service.stats()
    except Exception:
        return {"ok": False, "error": "queue unreadable"}
    st["ok"] = st["oldest_queued_seconds"] < QUEUE_STUCK_SECONDS and st["dead"] < get_settings().QUEUE_MAX_DEPTH
    return st


def readiness() -> dict[str, Any]:
    """Ready = can serve traffic (database + schema). Queue/worker problems are reported as `warnings`
    so a stalled worker pool does not take the API out of a load balancer."""
    db = check_database()
    out: dict[str, Any] = {"database": db}
    if not db["ok"]:
        return {"ready": False, "checks": out, "warnings": []}
    schema = check_schema()
    workers, queue = check_workers(), check_queue()
    out.update(schema=schema, workers=workers, queue=queue)
    warnings = []
    if not workers["ok"]:
        warnings.append("no live queue workers: ingested events will not be processed")
    if not queue["ok"]:
        warnings.append("queue is backed up or has dead-lettered jobs")
    if schema.get("ledger_has_required") is None:
        warnings.append("schema_migrations ledger not found: database was not migrated with database/migrate.sh")
    return {"ready": bool(db["ok"] and schema["ok"]), "checks": out, "warnings": warnings}


def system_status() -> dict[str, Any]:
    from app.detection.correlation import load_correlations
    from app.detection.engine import get_engine
    from app.services import llm_service

    s = get_settings()
    eng = get_engine()
    return {
        "version": s.APP_VERSION,
        "environment": s.APP_ENV,
        "readiness": readiness(),
        "detection": {"rules_version": eng.version, "rules": len(eng.rules), "correlations": len(load_correlations())},
        "llm": {"provider": s.LLM_PROVIDER, "configured": llm_service.llm_configured(), "model_override": s.LLM_MODEL_OVERRIDE or None},
        "ingest": {"triage_mode": s.INGEST_TRIAGE_MODE, "max_batch": s.INGEST_MAX_BATCH, "queue_max_depth": s.QUEUE_MAX_DEPTH,
                   "queue_max_depth_per_org": s.QUEUE_MAX_DEPTH_PER_ORG},
        "retention_days": {"events": s.RETENTION_EVENTS_DAYS, "evidence": s.RETENTION_EVIDENCE_DAYS,
                           "jobs": s.RETENTION_JOBS_DAYS, "pipeline_runs": s.RETENTION_RUNS_DAYS},
        "security": {"public_signup": s.ALLOW_PUBLIC_SIGNUP, "signed_ingest_available": len(s.APP_SECRET) >= 32,
                     "oidc_configured": bool(s.OIDC_ISSUER), "metrics_enabled": bool(s.METRICS_TOKEN),
                     "max_token_age_minutes": s.MAX_TOKEN_AGE_MINUTES or None},
    }


# ----------------------------------------------------------------------------- doctor
def doctor() -> list[dict[str, str]]:
    """Static + live checks with an actionable fix for each failure. status: ok | warn | fail."""
    s = get_settings()
    results: list[dict[str, str]] = []

    def add(status: str, check: str, detail: str, fix: str = "") -> None:
        results.append({"status": status, "check": check, "detail": detail, "fix": fix})

    prod = s.is_production
    add("ok" if not (prod and s.APP_DEBUG) else "fail", "APP_DEBUG", f"APP_ENV={s.APP_ENV}, APP_DEBUG={s.APP_DEBUG}",
        "Set APP_DEBUG=false in production.")
    add("ok" if "*" not in s.cors_origins_list else ("fail" if prod else "warn"), "CORS_ORIGINS", s.CORS_ORIGINS,
        "List your console origin(s) explicitly; '*' with credentials is unsafe.")
    add("ok" if len(s.SUPABASE_JWT_SECRET) >= 32 else ("fail" if prod else "warn"), "SUPABASE_JWT_SECRET",
        f"{len(s.SUPABASE_JWT_SECRET)} characters", "Use the project's JWT secret (>= 32 chars).")
    add("ok" if not s.ALLOW_PUBLIC_SIGNUP else ("warn" if prod else "ok"), "ALLOW_PUBLIC_SIGNUP", str(s.ALLOW_PUBLIC_SIGNUP),
        "Set ALLOW_PUBLIC_SIGNUP=false for a private deployment.")
    add("ok" if not s.SEED_DEMO_DATA else ("warn" if prod else "ok"), "SEED_DEMO_DATA", str(s.SEED_DEMO_DATA),
        "Set SEED_DEMO_DATA=false so new organizations start empty.")
    add("ok" if len(s.APP_SECRET) >= 32 else "warn", "APP_SECRET", "set" if s.APP_SECRET else "not set",
        "Set APP_SECRET (>= 32 random chars) to enable signed, replay-protected ingestion keys.")
    add("ok" if s.TRUST_PROXY_HEADERS or not prod else "warn", "TRUST_PROXY_HEADERS", str(s.TRUST_PROXY_HEADERS),
        "Behind a reverse proxy set TRUST_PROXY_HEADERS=true (and make the proxy overwrite X-Forwarded-For); otherwise all clients share the proxy's IP for rate limits.")
    add("ok" if s.METRICS_TOKEN else "warn", "METRICS_TOKEN", "set" if s.METRICS_TOKEN else "not set (GET /metrics is disabled)",
        "Set METRICS_TOKEN to expose Prometheus metrics.")

    from app.services import llm_service
    if s.LLM_PROVIDER == "none":
        add("warn", "LLM", "LLM_PROVIDER=none: detection and correlation run, agents are disabled", "Set a provider for AI triage/investigation.")
    elif llm_service.llm_configured():
        add("ok", "LLM", f"provider={s.LLM_PROVIDER}")
    else:
        add("warn", "LLM", f"provider={s.LLM_PROVIDER} is not configured: pipeline will run in rules-only degraded mode",
            "Set GROQ_API_KEY (groq) or LLM_BASE_URL (+LLM_API_KEY) for openai_compatible.")

    try:
        from app.detection.correlation import load_correlations
        from app.detection.engine import get_engine
        add("ok", "detection content", f"{len(get_engine().rules)} rules, {len(load_correlations())} correlations, rules {get_engine().version}")
    except Exception as exc:
        add("fail", "detection content", f"failed to load: {exc}", "Fix the rule/correlation YAML; the API will not start correctly.")

    db = check_database()
    if not db["ok"]:
        add("fail", "database", f"unreachable ({db.get('error')})", "Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY and network access.")
        return results
    add("ok", "database", f"reachable in {db['latency_ms']} ms")
    schema = check_schema()
    if schema["ok"]:
        add("ok", "schema", f"required tables present; ledger {'records' if schema['ledger_has_required'] else 'does not record'} {REQUIRED_MIGRATION}")
    else:
        add("fail", "schema", f"missing tables: {schema['missing_tables']}", "Run database/migrate.sh (apply 024 and 025; see docs/OPERATIONS.md).")
    w = check_workers()
    add("ok" if w["ok"] else "warn", "workers", f"{w.get('live', 0)} live (embedded={s.EMBEDDED_WORKER})",
        "Start a worker: `python -m app.worker`, or set EMBEDDED_WORKER=true.")
    q = check_queue()
    add("ok" if q.get("ok") else "warn", "queue", f"queued={q.get('queued')} running={q.get('running')} dead={q.get('dead')} oldest={q.get('oldest_queued_seconds')}s",
        "Inspect dead-lettered jobs and worker logs.")
    return results
