"""Process one stored event: detect -> correlate -> (if warranted) run the agent pipeline.

Idempotent by construction so a redelivered job is harmless: the event row records
``processed``; the pipeline de-duplicates by fingerprint; linking uses an upsert.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.agents.triage import TriageInput
from app.core import metrics
from app.core.config import get_settings
from app.core.logging import get_logger
from app.detection.engine import SEVERITY_RANK, RuleHit, summarize
from app.services import behavior_service, correlation_service, detection_service, pipeline_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def event_to_input(row: dict[str, Any]) -> TriageInput:
    raw = dict(row.get("raw_data") or {})
    asset_type = raw.pop("_asset_type", None)
    return TriageInput(
        title=row["title"],
        description=row.get("description"),
        source=row.get("source") or "other",
        event_type=row.get("event_type") or "generic.event",
        source_ip=str(row["source_ip"]) if row.get("source_ip") else None,
        destination_ip=str(row["destination_ip"]) if row.get("destination_ip") else None,
        source_port=row.get("source_port"),
        destination_port=row.get("destination_port"),
        username=row.get("username"),
        process_name=row.get("process_name"),
        command_line=row.get("command_line"),
        file_hash=row.get("file_hash"),
        asset_name=row.get("asset_name"),
        asset_type=asset_type,
        occurred_at=row.get("observed_at"),
        raw_data=raw,
    )


def process_event(org_id: str, event_id: str) -> dict[str, Any]:
    client = get_supabase_admin()
    rows = client.table("events").select("*").eq("organization_id", org_id).eq("id", event_id).limit(1).execute().data
    if not rows:
        return {"status": "missing"}  # purged or foreign: nothing to do, don't retry
    row = rows[0]
    settings = get_settings()
    inp = event_to_input(row)
    event_dict = inp.model_dump(mode="json")

    hits: list[RuleHit] = detection_service.evaluate(org_id, event_dict)
    try:   # behavioural analytics is additive: deterministic detections above stand even if baselines are unavailable
        behavior_hits = behavior_service.evaluate_and_learn(org_id, row, hits)
    except Exception:
        metrics.behavior_errors.inc()
        log.exception("behavior_evaluation_failed", event_id=event_id)
        behavior_hits = []
    hits = sorted([*hits, *behavior_hits], key=lambda h: (-SEVERITY_RANK[h.severity], -h.confidence))
    rule_summary = summarize(hits)
    # 1) persist this event's own detections BEFORE looking at its neighbours (see correlation_service.correlate)
    client.table("events").update({
        "detections": [h.as_dict() for h in hits], "mitre_tactics": rule_summary["tactics"],
        "mitre_techniques": rule_summary["techniques"], "alerted": bool(hits),
    }).eq("organization_id", org_id).eq("id", event_id).execute()
    # 2) correlate against the store; the ledger lets exactly one processor report each completed pattern
    correlated: list[RuleHit] = []
    try:
        correlated = correlation_service.correlate(org_id, {**row, "detections": [h.as_dict() for h in hits]}, hits)
    except Exception:  # correlation is additive; never lose the primary detection over it
        log.exception("correlation_failed", event_id=event_id)
    all_hits = sorted([*correlated, *hits], key=lambda h: (-SEVERITY_RANK[h.severity], -h.confidence))
    for h in all_hits:
        metrics.detections.inc(rule=h.rule_id, kind=h.kind)
    summary = summarize(all_hits)

    patch: dict[str, Any] = {
        "detections": [h.as_dict() for h in all_hits],
        "mitre_tactics": summary["tactics"],
        "mitre_techniques": summary["techniques"],
        "alerted": bool(all_hits),
        "processed": True,
        "processed_at": _now(),
    }
    if summary["severity_floor"]:
        patch["severity"] = summary["severity_floor"]
    client.table("events").update(patch).eq("organization_id", org_id).eq("id", event_id).execute()

    result: dict[str, Any] = {"status": "processed", "detections": [h.rule_id for h in all_hits]}
    mode = settings.INGEST_TRIAGE_MODE
    if mode == "none" or (mode == "matched" and not all_hits):
        return result

    run = pipeline_service.run_sync(
        org_id, inp, source=f"ingest:{row.get('source_system') or 'unknown'}", created_by=None,
        extra_hits=[*correlated, *behavior_hits],
    )
    threat_id = (run.get("summary") or {}).get("promoted_threat_id")
    result.update(run_id=run.get("run_id"), threat_id=threat_id,
                  deduplicated=bool((run.get("summary") or {}).get("deduplicated")))
    if threat_id:
        client.table("events").update({"threat_id": threat_id}).eq("organization_id", org_id).eq("id", event_id).execute()
        evidence = [{"organization_id": org_id, "threat_id": threat_id, "event_id": event_id, "role": "trigger"}]
        for hit in correlated:
            for eid in hit.evidence:
                if eid != event_id:
                    evidence.append({"organization_id": org_id, "threat_id": threat_id, "event_id": eid,
                                     "role": "supporting"})
        client.table("threat_events").upsert(evidence, on_conflict="threat_id,event_id").execute()
    return result
