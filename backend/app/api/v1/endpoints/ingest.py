"""Universal ingestion front door for collectors, SDKs, SIEM webhooks and API keys."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.agents.triage import TriageInput
from app.api.deps import CurrentUser, require_ingest
from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.ratelimit import rate_limit
from app.ingest import SUPPORTED_FORMATS, AdapterError, parse_payload
from app.services import pipeline_service

router = APIRouter(prefix="/ingest", tags=["ingest"])
log = get_logger(__name__)

MAX_BODY_BYTES = 1_000_000

_ingest_limit = rate_limit("ingest", per_minute=lambda: get_settings().LLM_RATE_LIMIT_PER_MINUTE * 3)


class IngestEventRequest(BaseModel):
    event: TriageInput
    source_system: str | None = Field(
        default=None,
        max_length=100,
        description="Name of the sending collector/source, e.g. 'tb-collector/auth.log'.",
    )
    collector_id: str | None = Field(
        default=None,
        max_length=100,
        description="Stable identifier of the collector instance that sent this.",
    )


class IngestEventResponse(BaseModel):
    stages: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)
    trace: list[dict[str, Any]] = Field(default_factory=list)
    run_id: str | None = None
    status: str | None = None


@router.post(
    "/event",
    response_model=IngestEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest one normalized security event and run the agent pipeline",
    dependencies=[Depends(_ingest_limit)],
)
def ingest_event(
    request: IngestEventRequest,
    response: Response,
    user: Annotated[CurrentUser, Depends(require_ingest)],
    background: Annotated[bool, Query(alias="async", description="Return 202 immediately; poll /orchestrator/runs/{id}")] = False,
) -> IngestEventResponse:
    """Accept a normalized event from a collector. Waits for the result unless ``?async=true``."""
    source = request.source_system or "ingest"
    log.info(
        "ingest_event_received",
        source_system=source,
        collector_id=request.collector_id,
        source_ip=request.event.source_ip,
        event_type=request.event.event_type,
        background=background,
    )
    if background:
        run = pipeline_service.submit_async(
            user.organization_id, request.event, source=source, created_by=user.display_name
        )
        response.status_code = status.HTTP_202_ACCEPTED
        return IngestEventResponse(run_id=run["id"], status="queued")
    result = pipeline_service.run_sync(
        user.organization_id, request.event, source=source, created_by=user.display_name
    )
    return IngestEventResponse(**result, status="completed")


class WebhookResponse(BaseModel):
    accepted: int
    runs: list[dict[str, str]]


async def _read_body(request: Request) -> Any:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large (max 1 MB).")
    raw = await request.body()
    if len(raw) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Payload too large (max 1 MB).")
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text  # raw text (CEF syslog lines)


@router.post(
    "/webhook/{fmt}",
    response_model=WebhookResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive SIEM / telemetry webhooks (wazuh, ecs, cef, cloudtrail, splunk, generic)",
    dependencies=[Depends(_ingest_limit)],
)
async def ingest_webhook(
    fmt: str,
    request: Request,
    user: Annotated[CurrentUser, Depends(require_ingest)],
) -> WebhookResponse:
    """Translate a vendor payload into events and queue each through the pipeline.

    Always asynchronous: a SIEM should not hold its connection open while LLM
    agents work. Track results via ``GET /orchestrator/runs``.
    """
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"Unsupported format {fmt!r}. Use one of: {', '.join(SUPPORTED_FORMATS)}.",
        )
    body = await _read_body(request)
    try:
        events = parse_payload(fmt, body, max_events=get_settings().INGEST_MAX_BATCH)
    except AdapterError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if not events:
        return WebhookResponse(accepted=0, runs=[])

    def _queue() -> list[dict[str, str]]:
        queued: list[dict[str, str]] = []
        for ev in events:
            row = pipeline_service.submit_async(
                user.organization_id, ev, source=f"webhook:{fmt}", created_by=user.display_name
            )
            queued.append({"run_id": row["id"], "title": ev.title[:120]})
        return queued

    runs = await run_in_threadpool(_queue)  # DB writes must not block the event loop
    log.info("ingest_webhook_accepted", fmt=fmt, count=len(runs))
    return WebhookResponse(accepted=len(runs), runs=runs)
