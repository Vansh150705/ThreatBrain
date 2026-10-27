"""The agent orchestrator.

One security event goes in; a traced, evidence-backed investigation comes out.

    detection (rules) -> de-dup -> triage (LLM) -> reconcile -> promote
        -> threat intel -> correlate / investigate -> [response | forensics | compliance]

Design rules:
  * Deterministic stages (rules, de-dup, correlation, reconciliation) run without
    an LLM, so a model outage degrades the pipeline instead of stopping it.
  * Every stage is timed, bounded (timeout + limited retries) and traced; one
    failing stage never aborts the others unless a later stage truly depends on it.
  * Earlier findings travel to later agents as structured shared context.
  * The orchestrator never executes a response action. It only queues
    recommendations for human approval (or records a dry-run simulation).
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID

from pydantic import ValidationError

from app.agents.base import AgentConfigError, AgentInput
from app.agents.compliance import ComplianceAgent, ComplianceInput
from app.agents.forensics import ForensicsAgent, ForensicsInput
from app.agents.investigation import InvestigationAgent, InvestigationInput, InvestigationOutput
from app.agents.response import ResponseAgent, ResponseInput, ResponseOutput
from app.agents.threat_intel import ThreatIntelAgent, ThreatIntelInput
from app.agents.triage import TriageAgent, TriageInput, TriageOutput
from app.agents.triage.schemas import EvidenceItem
from app.core.config import get_settings
from app.core.logging import get_logger
from app.detection.engine import SEVERITY_RANK, get_engine, summarize
from app.detection.fingerprint import event_fingerprint
from app.detection.risk import compute_risk_score
from app.schemas.common import SeverityLevel
from app.services import incident_service, notifier
from app.services.llm_service import LLMError
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

STAGE_ORDER = (
    "detection",
    "triage",
    "threat_intel",
    "investigation",
    "response",
    "forensics",
    "compliance",
)

# Two pools on purpose. ``_call`` threads run the bounded agent calls;
# ``_fanout`` threads only wait on them. Keeping waiters and workers apart means
# concurrent pipelines can never starve each other into a deadlock.
_pool: ThreadPoolExecutor | None = None
_fanout: ThreadPoolExecutor | None = None


def _get_pool() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(
            max_workers=max(6, get_settings().PIPELINE_WORKERS * 4), thread_name_prefix="stage-call"
        )
    return _pool


def _get_fanout() -> ThreadPoolExecutor:
    global _fanout
    if _fanout is None:
        _fanout = ThreadPoolExecutor(
            max_workers=max(6, get_settings().PIPELINE_WORKERS * 4), thread_name_prefix="stage-wait"
        )
    return _fanout


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Stage execution (timeout + bounded retry + trace)
# --------------------------------------------------------------------------
class _Run:
    """Accumulates stage results and the execution trace for one pipeline."""

    def __init__(self) -> None:
        self.stages: dict[str, dict[str, Any]] = {}
        self.trace: list[dict[str, Any]] = []

    def record(
        self,
        name: str,
        status: str,
        *,
        started: float | None = None,
        attempts: int = 0,
        **fields: Any,
    ) -> dict[str, Any]:
        stage = {"status": status, **fields}
        if attempts:
            stage["attempts"] = attempts
        self.stages[name] = stage
        self.trace.append(
            {
                "stage": name,
                "status": status,
                "at": _now(),
                "duration_ms": int((time.perf_counter() - started) * 1000) if started else 0,
                "attempts": attempts,
                "run_id": fields.get("run_id"),
                "error": fields.get("error"),
                "reason": fields.get("reason"),
            }
        )
        return stage

    def skip(self, name: str, reason: str) -> None:
        self.record(name, "skipped", reason=reason)

    def ok(self, name: str) -> bool:
        return self.stages.get(name, {}).get("status") in ("ok", "degraded")


def _safe_error(exc: BaseException) -> str:
    """Error text that is safe to show analysts (no stack, bounded)."""
    if isinstance(exc, ValidationError):
        return "The model's output did not match the expected schema."
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def _call_with_timeout(fn: Callable[[], Any], timeout: float) -> Any:
    future: Future = _get_pool().submit(fn)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout as exc:
        future.cancel()
        raise TimeoutError(f"stage exceeded {int(timeout)}s") from exc


def _run_agent_stage(
    run: _Run,
    name: str,
    fn: Callable[[], dict[str, Any]],
    *,
    retries: int = 1,
) -> dict[str, Any] | None:
    """Run ``fn`` (returns the stage's result fields) with timeout and retry.

    Retries only cover failures a fresh attempt can plausibly fix: a model that
    returned output not matching the schema (non-deterministic). Transport errors
    were already retried inside the LLM client, and misconfiguration/timeouts
    fail fast. Returns the fields on success, ``None`` on failure.
    """
    timeout = get_settings().PIPELINE_STAGE_TIMEOUT_SECONDS
    started = time.perf_counter()
    attempts = 0
    last_exc: BaseException | None = None
    while attempts <= retries:
        attempts += 1
        try:
            fields = _call_with_timeout(fn, timeout)
            run.record(name, "ok", started=started, attempts=attempts, **fields)
            return fields
        except ValidationError as exc:
            last_exc = exc
            log.warning("pipeline_stage_retryable_failure", stage=name, attempt=attempts, error=_safe_error(exc))
            continue
        except (LLMError, AgentConfigError, TimeoutError) as exc:
            last_exc = exc
            break
        except Exception as exc:  # unexpected: record and move on, don't crash the pipeline
            last_exc = exc
            log.exception("pipeline_stage_failed", stage=name)
            break
    run.record(name, "failed", started=started, attempts=attempts, error=_safe_error(last_exc or Exception("unknown")))
    return None


def _agent_fields(result: Any, **extra: Any) -> dict[str, Any]:
    return {
        "run_id": result.run_id,
        "latency_ms": result.latency_ms,
        "tokens": result.total_tokens,
        **extra,
    }


# --------------------------------------------------------------------------
# Deterministic reconciliation of the LLM verdict with rule evidence
# --------------------------------------------------------------------------
def reconcile_verdict(
    verdict: TriageOutput, detection: dict[str, Any]
) -> tuple[TriageOutput, dict[str, Any]]:
    """Merge the model's verdict with deterministic rule evidence.

    * A strong rule match (confidence >= 70) puts a floor under severity: the
      model may add nuance but cannot talk a known-bad pattern down.
    * MITRE IDs from rules are merged in; rule hits become cited evidence.
    * Medium-or-worse severity with rule corroboration is always promoted.
    Everything changed is listed in the returned audit record.
    """
    notes: list[str] = []
    out = verdict.model_copy(deep=True)
    original = out.severity.value

    if detection.get("matched"):
        floor = detection["severity_floor"]
        rule_conf = int(detection["confidence"])
        if SEVERITY_RANK[floor] > SEVERITY_RANK[out.severity.value] and rule_conf >= 70:
            out.severity = SeverityLevel(floor)
            out.confidence = max(out.confidence, rule_conf)
            notes.append(f"severity raised {original} -> {floor} by detection rule floor")
        for t in detection["tactics"]:
            if t not in out.mitre_tactics:
                out.mitre_tactics.append(t)
        for t in detection["techniques"]:
            if t not in out.mitre_techniques:
                out.mitre_techniques.append(t)
        for tag in detection["tags"]:
            if tag not in out.tags:
                out.tags.append(tag)
        for hit in detection["rules"][:5]:
            out.evidence.append(
                EvidenceItem(
                    source=f"rule:{hit['rule_id']}",
                    detail=f"{hit['name']} (matched on {', '.join(hit['matched_fields']) or 'event'})",
                )
            )
        if SEVERITY_RANK[out.severity.value] >= SEVERITY_RANK["medium"] and not out.promote_to_threat:
            out.promote_to_threat = True
            notes.append("promoted to threat: medium+ severity corroborated by detection rules")

    return out, {
        "adjusted": bool(notes),
        "notes": notes,
        "llm_severity": original,
        "final_severity": out.severity.value,
        "rule_ids": [r["rule_id"] for r in detection.get("rules", [])],
    }


def verdict_from_rules(event: TriageInput, detection: dict[str, Any]) -> TriageOutput:
    """Degraded-mode verdict when the LLM is unavailable but rules matched."""
    floor = detection["severity_floor"]
    top = detection["rules"][0]
    return TriageOutput(
        severity=SeverityLevel(floor),
        confidence=int(detection["confidence"]),
        title=event.title[:300],
        description=(
            f"{top['name']}. Classified from deterministic detection rules because the "
            "language model was unavailable; review before acting."
        ),
        reasoning="LLM unavailable: verdict derived solely from matched detection rules "
        + ", ".join(r["rule_id"] for r in detection["rules"][:5]),
        evidence=[
            EvidenceItem(source=f"rule:{r['rule_id']}", detail=r["name"]) for r in detection["rules"][:5]
        ],
        mitre_tactics=detection["tactics"],
        mitre_techniques=detection["techniques"],
        tags=detection["tags"] + ["degraded-mode"],
        promote_to_threat=SEVERITY_RANK[floor] >= SEVERITY_RANK["medium"],
    )


# --------------------------------------------------------------------------
# De-duplication
# --------------------------------------------------------------------------
def find_duplicate_threat(org_id: str, fingerprint: str) -> dict[str, Any] | None:
    """An active threat with the same fingerprint seen within the dedup window."""
    window = get_settings().DEDUP_WINDOW_MINUTES
    if window <= 0:
        return None
    since = (datetime.now(timezone.utc) - timedelta(minutes=window)).isoformat()
    try:
        rows = (
            get_supabase_admin()
            .table("threats")
            .select("id, short_id, event_count, incident_id")
            .eq("organization_id", org_id)
            .eq("fingerprint", fingerprint)
            .is_("deleted_at", "null")
            .in_("status", ["open", "investigating", "contained"])
            .gte("last_seen_at", since)
            .order("last_seen_at", desc=True)
            .limit(1)
            .execute()
            .data
            or []
        )
    except Exception:
        # e.g. migration 023 not applied yet: keep ingesting, just without de-dup
        log.warning("dedup_lookup_failed", exc_info=True)
        return None
    return rows[0] if rows else None


def _bump_duplicate(org_id: str, dup: dict[str, Any], occurred: str | None) -> int:
    count = int(dup.get("event_count") or 1) + 1
    get_supabase_admin().table("threats").update(
        {"event_count": count, "last_seen_at": occurred or _now()}
    ).eq("organization_id", org_id).eq("id", dup["id"]).execute()
    if dup.get("incident_id"):
        try:
            incident_service.refresh_aggregates(org_id, dup["incident_id"])
        except Exception:
            log.warning("dedup_incident_refresh_failed", exc_info=True)
    return count


# --------------------------------------------------------------------------
# Main pipeline
# --------------------------------------------------------------------------
def run_full_pipeline(
    *,
    organization_id: UUID | str,
    event: TriageInput,
    primary_asset_id: str | None = None,
    promote_threats: bool = True,
    run_threat_intel: bool = True,
    run_investigation: bool = True,
    run_response: bool = True,
    run_forensics: bool = True,
    run_compliance: bool = True,
    investigation_lookback_hours: int = 72,
    response_mode: str = "recommend",
    deduplicate: bool = True,
) -> dict[str, Any]:
    """Run one event through every stage. Returns ``{stages, summary, trace}``.

    ``response_mode``: ``recommend`` queues validated actions for human approval;
    ``simulate`` records what would be proposed without queueing anything.
    """
    settings = get_settings()
    org_id = str(organization_id)
    run = _Run()
    event_dict = event.model_dump(mode="json")
    context: dict[str, Any] = {}

    summary: dict[str, Any] = {
        "incident_short_id": None,
        "promoted_threat_id": None,
        "promoted_threat_short_id": None,
        "deduplicated": False,
        "duplicate_of": None,
        "degraded": False,
        "final_severity": None,
        "risk_score": None,
    }

    def _finish() -> dict[str, Any]:
        for name in STAGE_ORDER:
            if name not in run.stages:
                run.skip(name, "not reached")
        statuses = [s["status"] for s in run.stages.values()]
        summary.update(
            stages_run=sum(1 for s in statuses if s != "skipped"),
            stages_succeeded=sum(1 for s in statuses if s in ("ok", "degraded")),
            stages_failed=sum(1 for s in statuses if s == "failed"),
            stages_skipped=sum(1 for s in statuses if s == "skipped"),
            stages_degraded=sum(1 for s in statuses if s == "degraded"),
        )
        ordered = {n: run.stages[n] for n in STAGE_ORDER if n in run.stages}
        log.info("orchestrator_pipeline_completed", **{k: v for k, v in summary.items() if not isinstance(v, dict)})
        return {"stages": ordered, "summary": summary, "trace": run.trace}

    # ---- Stage 0: deterministic detection --------------------------------
    t0 = time.perf_counter()
    hits = get_engine().evaluate(event_dict)
    detection = summarize(hits)
    fingerprint = event_fingerprint(event_dict, [h.rule_id for h in hits])
    context["detection"] = {
        k: detection[k] for k in ("matched", "severity_floor", "confidence", "techniques", "tags")
    } | {"rule_ids": [r["rule_id"] for r in detection["rules"]]}
    run.record(
        "detection", "ok", started=t0, verdict=detection | {"fingerprint": fingerprint},
        latency_ms=int((time.perf_counter() - t0) * 1000), tokens=0,
    )

    # ---- De-duplication: fold repeats into the existing threat -----------
    if promote_threats and deduplicate:
        dup = find_duplicate_threat(org_id, fingerprint)
        if dup is not None:
            count = _bump_duplicate(
                org_id, dup, event.occurred_at.isoformat() if event.occurred_at else None
            )
            summary.update(deduplicated=True, duplicate_of=dup["short_id"], event_count=count)
            run.skip("triage", f"duplicate of {dup['short_id']} ({count} events folded)")
            for name in STAGE_ORDER[2:]:
                run.skip(name, "event folded into an existing threat")
            return _finish()

    # ---- Stage 1: triage (LLM) + reconcile -------------------------------
    triage_holder: dict[str, Any] = {}

    def _triage() -> dict[str, Any]:
        agent = TriageAgent()
        res = agent.run(
            AgentInput(
                organization_id=org_id,
                trigger_type="chained",
                payload=event_dict,
                context=context,
            )
        )
        triage_holder["agent"], triage_holder["result"] = agent, res
        return _agent_fields(res, verdict=res.output)

    triage_fields = _run_agent_stage(run, "triage", _triage)
    raw_verdict: TriageOutput | None = None
    if triage_fields is not None:
        try:
            raw_verdict = TriageOutput.model_validate(triage_holder["result"].output)
        except ValidationError:
            raw_verdict = None
    elif detection["matched"] and detection["severity_floor"]:
        # LLM unavailable/failing: fall back to a rules-only verdict, clearly marked.
        raw_verdict = verdict_from_rules(event, detection)
        summary["degraded"] = True
        failed = run.stages["triage"]
        run.record(
            "triage", "degraded", attempts=failed.get("attempts", 0),
            verdict=raw_verdict.model_dump(mode="json"), error=failed.get("error"),
            reason="LLM unavailable; verdict derived from deterministic rules",
            latency_ms=0, tokens=0,
        )

    if raw_verdict is None:
        for name in STAGE_ORDER[2:]:
            run.skip(name, "triage produced no verdict")
        return _finish()

    verdict, reconciliation = reconcile_verdict(raw_verdict, detection)
    run.stages["triage"]["verdict"] = verdict.model_dump(mode="json")
    run.stages["triage"]["reconciliation"] = reconciliation
    context["triage"] = {
        "severity": verdict.severity.value,
        "confidence": verdict.confidence,
        "title": verdict.title,
        "mitre_techniques": verdict.mitre_techniques,
        "evidence": [e.model_dump() for e in verdict.evidence][:8],
    }
    summary["final_severity"] = verdict.severity.value

    # ---- Promote to threat ----------------------------------------------
    threat_id = threat_short_id = None
    if promote_threats and verdict.promote_to_threat:
        risk, _ = compute_risk_score(
            severity=verdict.severity.value,
            confidence=verdict.confidence,
            asset_criticality=event.asset_criticality,
            rule_hit_count=len(hits),
        )
        try:
            agent = triage_holder.get("agent") or TriageAgent()
            run_id = triage_holder["result"].run_id if "result" in triage_holder else ""
            threat_id = agent.promote_to_threat(
                organization_id=org_id,
                triage_input=event,
                triage_output=verdict,
                agent_run_id=run_id,
                primary_asset_id=primary_asset_id,
                fingerprint=fingerprint,
                rule_hits=detection["rules"],
                risk_score=risk,
                reconciliation=reconciliation,
            )
            row = (
                get_supabase_admin().table("threats").select("short_id, risk_score")
                .eq("organization_id", org_id).eq("id", threat_id).limit(1).execute().data
            )
            threat_short_id = row[0]["short_id"] if row else None
            summary.update(
                promoted_threat_id=threat_id,
                promoted_threat_short_id=threat_short_id,
                risk_score=risk,
            )
            run.stages["triage"]["promoted_threat_id"] = threat_id
            run.stages["triage"]["promoted_threat_short_id"] = threat_short_id
            context["threat"] = {"short_id": threat_short_id, "risk_score": risk}
        except Exception as exc:
            log.exception("orchestrator_promote_failed")
            run.stages["triage"]["promote_error"] = _safe_error(exc)

    if threat_id is None:
        reason = "event was not promoted to a threat"
        for name in STAGE_ORDER[2:]:
            run.skip(name, reason)
        return _finish()

    # ---- Stage 2: threat intel ------------------------------------------
    if not run_threat_intel:
        run.skip("threat_intel", "disabled by flag")
    elif not event.source_ip:
        run.skip("threat_intel", "no source_ip in event")
    else:
        def _intel() -> dict[str, Any]:
            res = ThreatIntelAgent().run(
                AgentInput(
                    organization_id=org_id,
                    trigger_type="chained",
                    payload=ThreatIntelInput(
                        ip_address=event.source_ip, context=event.description or event.title
                    ).model_dump(),
                    context=context,
                )
            )
            return _agent_fields(res, verdict=res.output)

        intel = _run_agent_stage(run, "threat_intel", _intel)
        if intel is not None:
            out = intel["verdict"]
            context["threat_intel"] = {
                k: out.get(k)
                for k in ("reputation", "composite_score", "feeds_used", "country_code", "summary")
            }
            _apply_intel_to_threat(org_id, threat_id, verdict, event, hits, out, summary)

    # ---- Stage 3: correlate / investigate -------------------------------
    incident_id: str | None = None
    incident_short_id: str | None = None
    new_incident = False
    if not run_investigation:
        run.skip("investigation", "disabled by flag")
    else:
        incident_id, incident_short_id, new_incident = _correlate(
            run, org_id, event, threat_id, threat_short_id, verdict,
            investigation_lookback_hours, context,
        )
    summary["incident_short_id"] = incident_short_id

    # ---- Stages 4-6 need an incident -------------------------------------
    if incident_short_id is None:
        reason = "no incident produced by investigation"
        for name, enabled in (("response", run_response), ("forensics", run_forensics), ("compliance", run_compliance)):
            run.skip(name, reason if enabled else "disabled by flag")
        return _finish()

    if new_incident:
        try:
            row = (
                get_supabase_admin().table("incidents")
                .select("short_id, title, severity, priority, threat_count, source_ips")
                .eq("organization_id", org_id).eq("id", incident_id).limit(1).execute().data
            )
            if row:
                notifier.notify_incident(row[0])
        except Exception:
            log.warning("incident_notification_failed", exc_info=True)

    futures: dict[str, Future] = {}

    def _response() -> dict[str, Any]:
        agent = ResponseAgent()
        res = agent.run(
            AgentInput(
                organization_id=org_id,
                trigger_type="chained",
                payload=ResponseInput(
                    incident_short_id=incident_short_id, dry_run=(response_mode == "simulate")
                ).model_dump(),
                context=context,
            )
        )
        out = ResponseOutput.model_validate(res.output)
        out = agent.apply_actions(
            organization_id=org_id, verdict=out, agent_run_id=res.run_id,
            dry_run=(response_mode == "simulate"),
        )
        _persist_playbook_runs(org_id, incident_id, out, res.run_id)
        return _agent_fields(res, verdict=out.model_dump(mode="json"))

    def _forensics() -> dict[str, Any]:
        res = ForensicsAgent().run(
            AgentInput(
                organization_id=org_id, trigger_type="chained",
                payload=ForensicsInput(incident_short_id=incident_short_id).model_dump(),
                context=context,
            )
        )
        _persist_timeline(org_id, incident_id, res.output, res.run_id)
        return _agent_fields(res, verdict=res.output)

    def _compliance() -> dict[str, Any]:
        res = ComplianceAgent().run(
            AgentInput(
                organization_id=org_id, trigger_type="chained",
                payload=ComplianceInput(incident_short_id=incident_short_id).model_dump(),
                context=context,
            )
        )
        _persist_compliance(org_id, incident_id, res.output, res.run_id)
        return _agent_fields(res, verdict=res.output)

    # Response, forensics and compliance are independent: run them concurrently.
    stage_fns = (
        ("response", run_response, _response),
        ("forensics", run_forensics, _forensics),
        ("compliance", run_compliance, _compliance),
    )
    sub_runs: dict[str, _Run] = {}
    for name, enabled, fn in stage_fns:
        if not enabled:
            run.skip(name, "disabled by flag")
            continue
        sub = sub_runs[name] = _Run()
        futures[name] = _get_fanout().submit(_run_agent_stage, sub, name, fn)
    for name, fut in futures.items():
        try:
            fut.result(timeout=settings.PIPELINE_STAGE_TIMEOUT_SECONDS * 2 + 30)
        except Exception as exc:  # _run_agent_stage handles its own errors; this is belt and braces
            sub_runs[name].record(name, "failed", error=_safe_error(exc))
        run.stages[name] = sub_runs[name].stages[name]
        run.trace.extend(sub_runs[name].trace)

    return _finish()


# --------------------------------------------------------------------------
# Stage helpers
# --------------------------------------------------------------------------
def _apply_intel_to_threat(
    org_id: str,
    threat_id: str,
    verdict: TriageOutput,
    event: TriageInput,
    hits: list[Any],
    intel: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    """Fold external intel back into the threat: enrichment blob + re-scored risk."""
    try:
        composite = intel.get("composite_score")
        risk, breakdown = compute_risk_score(
            severity=verdict.severity.value,
            confidence=verdict.confidence,
            asset_criticality=event.asset_criticality,
            intel_score=composite,
            rule_hit_count=len(hits),
        )
        client = get_supabase_admin()
        current = (
            client.table("threats").select("tags").eq("organization_id", org_id)
            .eq("id", threat_id).limit(1).execute().data or [{}]
        )[0]
        tags = list(current.get("tags") or [])
        if intel.get("reputation") == "malicious" and "known-malicious-source" not in tags:
            tags.append("known-malicious-source")
        client.table("threats").update(
            {
                "enrichment": {
                    "threat_intel": {
                        "reputation": intel.get("reputation"),
                        "composite_score": composite,
                        "feeds_used": intel.get("feeds_used"),
                        "feed_scores": intel.get("feed_scores"),
                        "country_code": intel.get("country_code"),
                        "summary": intel.get("summary"),
                    },
                    "risk_breakdown": breakdown,
                },
                "risk_score": risk,
                "tags": tags,
            }
        ).eq("organization_id", org_id).eq("id", threat_id).execute()
        summary["risk_score"] = risk
    except Exception:
        log.exception("apply_intel_to_threat_failed")


def _correlate(
    run: _Run,
    org_id: str,
    event: TriageInput,
    threat_id: str,
    threat_short_id: str | None,
    verdict: TriageOutput,
    lookback_hours: int,
    context: dict[str, Any],
) -> tuple[str | None, str | None, bool]:
    """Attach to an existing incident, else investigate, else single-threat incident.

    Returns (incident_id, short_id, is_new_incident).
    """
    started = time.perf_counter()
    source_ips = [event.source_ip] if event.source_ip else []

    # (a) deterministic correlation with an already-open incident
    try:
        match = incident_service.find_correlated_incident(
            org_id, source_ips=source_ips, window_hours=get_settings().CORRELATION_WINDOW_HOURS
        )
    except Exception:
        log.exception("correlation_lookup_failed")
        match = None
    if match is not None:
        incident_service.attach_threat(org_id, match["id"], threat_id)
        run.record(
            "investigation", "ok", started=started, attempts=1,
            verdict={
                "mode": "correlated_existing_incident",
                "summary": f"Threat {threat_short_id} shares source "
                f"{', '.join(source_ips)} with open incident {match['short_id']}; attached.",
                "incident_short_id": match["short_id"],
                "groups": [], "unrelated_threat_short_ids": [],
            },
            incidents_created=[], latency_ms=int((time.perf_counter() - started) * 1000), tokens=0,
        )
        return match["id"], match["short_id"], False

    # (b) LLM investigation across unlinked recent threats
    holder: dict[str, Any] = {}

    def _investigate() -> dict[str, Any]:
        agent = InvestigationAgent()
        res = agent.run(
            AgentInput(
                organization_id=org_id,
                trigger_type="chained",
                payload=InvestigationInput(
                    lookback_hours=lookback_hours, max_threats=10, min_severity="low"
                ).model_dump(),
                context=context,
            )
        )
        out = InvestigationOutput.model_validate(res.output)
        created = agent.create_incidents_from_output(
            organization_id=org_id, verdict=out, agent_run_id=res.run_id
        )
        holder["created"] = created
        return _agent_fields(res, verdict=out.model_dump(mode="json"), incidents_created=created)

    fields = _run_agent_stage(run, "investigation", _investigate)
    created = holder.get("created") or []
    if created:
        # the new threat's incident, if it was grouped
        row = (
            get_supabase_admin().table("threats").select("incident_id")
            .eq("organization_id", org_id).eq("id", threat_id).limit(1).execute().data
        )
        linked = row[0]["incident_id"] if row else None
        for c in created:
            if c.get("incident_id") == linked:
                return c["incident_id"], c["short_id"], True
        # the investigation grouped other threats but not this one: fall through

    # (c) a lone high/critical threat still deserves its own case
    if verdict.severity.value in ("high", "critical"):
        try:
            inc = incident_service.create_incident(
                org_id,
                title=verdict.title,
                description=verdict.description,
                severity=verdict.severity.value,
                confidence=verdict.confidence,
                threat_ids=[threat_id],
                ai_summary={"source": "single_threat_fallback", "evidence": context.get("triage", {}).get("evidence", [])},
            )
            log.info("orchestrator_single_threat_incident_created", incident_short_id=inc.get("short_id"))
            run.stages["investigation"]["fallback"] = (
                f"single-threat incident {inc.get('short_id')} created"
            )
            return inc["id"], inc["short_id"], True
        except Exception:
            log.exception("orchestrator_incident_fallback_failed")
    return None, None, False


def _persist_timeline(org_id: str, incident_id: str | None, output: dict[str, Any], run_id: str) -> None:
    """Write the forensic timeline onto the incident so the console can show it."""
    if not incident_id:
        return
    events = [
        {
            "ts": e.get("timestamp"),
            "event": e.get("description"),
            "phase": e.get("phase"),
            "actor": e.get("actor"),
            "target": e.get("target"),
            "threat_short_id": e.get("threat_short_id"),
            "artifacts": e.get("artifacts") or [],
            "source": "forensics_agent",
            "run_id": run_id,
        }
        for e in (output.get("timeline") or [])
        if isinstance(e, dict)
    ]
    client = get_supabase_admin()
    cur = (
        client.table("incidents").select("ai_summary").eq("organization_id", org_id)
        .eq("id", incident_id).limit(1).execute().data or [{}]
    )[0].get("ai_summary") or {}
    cur["forensics"] = {
        "run_id": run_id,
        "executive_summary": output.get("executive_summary"),
        "attack_narrative": output.get("attack_narrative"),
        "key_artifacts": output.get("key_artifacts") or [],
        "evidence_recommendations": output.get("evidence_recommendations") or [],
    }
    client.table("incidents").update({"timeline": events, "ai_summary": cur}).eq(
        "organization_id", org_id
    ).eq("id", incident_id).execute()


def _persist_playbook_runs(org_id: str, incident_id: str | None, out: ResponseOutput, run_id: str) -> None:
    if not incident_id:
        return
    runs = [
        {
            "ts": _now(),
            "playbook": a.playbook_name,
            "action_type": a.action_type,
            "target": a.target,
            "status": a.status,  # recommended | simulated | skipped; "executed" only via the approval queue
            "skip_reason": a.skip_reason,
            "rationale": a.rationale,
            "response_run_id": run_id,
        }
        for a in out.actions
    ]
    client = get_supabase_admin()
    existing = (
        client.table("incidents").select("playbook_runs").eq("organization_id", org_id)
        .eq("id", incident_id).limit(1).execute().data or [{}]
    )[0].get("playbook_runs") or []
    client.table("incidents").update({"playbook_runs": [*existing, *runs][-100:]}).eq(
        "organization_id", org_id
    ).eq("id", incident_id).execute()


def _persist_compliance(org_id: str, incident_id: str | None, output: dict[str, Any], run_id: str) -> None:
    if not incident_id:
        return
    client = get_supabase_admin()
    cur = (
        client.table("incidents").select("ai_summary").eq("organization_id", org_id)
        .eq("id", incident_id).limit(1).execute().data or [{}]
    )[0].get("ai_summary") or {}
    cur["compliance"] = {
        "run_id": run_id,
        "overall_compliance_risk": output.get("overall_compliance_risk"),
        "applicable_regulations": output.get("applicable_regulations") or [],
        "mandatory_deadlines": output.get("mandatory_deadlines") or [],
    }
    client.table("incidents").update({"ai_summary": cur}).eq("organization_id", org_id).eq(
        "id", incident_id
    ).execute()


__all__ = ["run_full_pipeline", "reconcile_verdict", "verdict_from_rules", "STAGE_ORDER"]
