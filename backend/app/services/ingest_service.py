"""Accept events: validate -> persist (idempotent) -> enqueue for asynchronous processing.

The HTTP request never waits for detection, correlation or LLM agents; it only needs
the event durably stored and a job durably queued, so a collector or SIEM gets a fast
answer and nothing is lost if the process dies a moment later.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.agents.triage import TriageInput
from app.core import metrics
from app.core.logging import get_logger
from app.services import queue_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

EVENT_SOURCES = {"edr", "firewall", "cloud_audit", "siem", "dns", "application", "authentication",
                 "email", "manual", "simulator", "other"}
PROCESS_KIND = "event.process"


def normalize_source(source: str | None) -> str:
    s = (source or "other").strip().lower()
    return s if s in EVENT_SOURCES else "other"


def idempotency_key(source_system: str, event: TriageInput) -> str:
    """Stable hash of the event's content. A redelivery of the same event hashes the same.

    ``occurred_at`` participates, so two genuinely distinct events with identical content at
    different times are both kept; an event with no timestamp collapses identical repeats
    (use a timestamp or an explicit ``raw_data.event_id`` if you need to keep every repeat).
    """
    body = event.model_dump(mode="json")
    explicit = (body.get("raw_data") or {}).get("event_id") or (body.get("raw_data") or {}).get("id")
    basis = {"src": source_system, "id": str(explicit)} if explicit else {"src": source_system, "e": body}
    return hashlib.sha256(json.dumps(basis, sort_keys=True, default=str).encode()).hexdigest()


def _row(org_id: str, event: TriageInput, source_system: str, key: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "organization_id": org_id,
        "source": normalize_source(event.source),
        "source_system": source_system[:100],
        "event_type": event.event_type[:100],
        "title": event.title[:500],
        "description": event.description,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "username": event.username,
        "process_name": event.process_name,
        "command_line": event.command_line,
        "file_hash": event.file_hash,
        "asset_name": event.asset_name,
        "raw_data": {**(event.raw_data or {}), **({"_asset_type": event.asset_type} if event.asset_type else {})},
        "idempotency_key": key,
    }
    if event.occurred_at:
        row["observed_at"] = event.occurred_at.isoformat()
    return {k: v for k, v in row.items() if v is not None}


def accept_events(org_id: str, events: list[TriageInput], *, source_system: str) -> dict[str, Any]:
    """Store + enqueue. Raises ``QueueFull`` (-> HTTP 503) when over the backpressure ceiling."""
    if not events:
        return {"accepted": 0, "duplicates": 0, "event_ids": []}
    queue_service.check_capacity(org_id, incoming=len(events))
    keyed: dict[str, TriageInput] = {}
    for ev in events:  # collapse duplicates inside one batch first
        keyed.setdefault(idempotency_key(source_system, ev), ev)
    rows = [_row(org_id, ev, source_system, key) for key, ev in keyed.items()]
    stored = (
        get_supabase_admin().table("events")
        .upsert(rows, on_conflict="organization_id,idempotency_key", ignore_duplicates=True)
        .execute().data or []
    )
    if stored:
        queue_service.enqueue_many(
            org_id, PROCESS_KIND, [{"event_id": r["id"], "source_system": source_system} for r in stored]
        )
    duplicates = len(events) - len(stored)
    metrics.events_ingested.inc(len(stored), outcome="accepted")
    metrics.events_ingested.inc(duplicates, outcome="duplicate")
    log.info("events_accepted", accepted=len(stored), duplicates=duplicates, source_system=source_system)
    return {"accepted": len(stored), "duplicates": duplicates, "event_ids": [r["id"] for r in stored]}
