from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from app.api.deps import CurrentUser, get_current_user
from app.schemas.incident import (
    IncidentDetail,
    IncidentListItem,
    IncidentListResponse,
)
from app.services import incident_service
from app.services.supabase_client import get_supabase_admin

router = APIRouter(prefix="/incidents", tags=["incidents"])


# List incidents
@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    severity: Annotated[str | None, Query()] = None,
    incident_status: Annotated[str | None, Query(alias="status")] = None,
    priority: Annotated[str | None, Query()] = None,
    sort_by: Annotated[str, Query()] = "created_at",
    sort_dir: Annotated[str, Query()] = "desc",
) -> IncidentListResponse:
    """List incidents for the caller's organization with filters, sorting, and pagination."""
    result = incident_service.list_incidents(
        organization_id=user.organization_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=incident_status,
        priority=priority,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return IncidentListResponse(
        items=[IncidentListItem(**row) for row in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        has_more=result["has_more"],
    )


# Detail by UUID or short_id
@router.get("/{identifier}", response_model=IncidentDetail)
async def get_incident(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> IncidentDetail:
    """Fetch a single incident by UUID or short_id."""
    incident = None
    try:
        uuid_value = UUID(identifier)
        incident = incident_service.get_incident_detail(user.organization_id, uuid_value)
    except ValueError:
        incident = incident_service.get_incident_by_short_id(user.organization_id, identifier)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found",
        )

    return IncidentDetail(**incident)


# Threats grouped under an incident
@router.get("/{identifier}/threats")
async def get_incident_threats(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    """Fetch the threats that belong to an incident."""
    incident = None
    try:
        uuid_value = UUID(identifier)
        incident = incident_service.get_incident_detail(user.organization_id, uuid_value)
    except ValueError:
        incident = incident_service.get_incident_by_short_id(user.organization_id, identifier)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found",
        )

    threats = incident_service.list_threats_for_incident(
        user.organization_id,
        UUID(incident["id"]),
    )
    return {"items": threats, "total": len(threats)}


def _md_list(values: Any) -> str:
    if not values:
        return "none recorded"
    if isinstance(values, list):
        return ", ".join(str(v) for v in values)
    return str(values)


# download an incident report as markdown
@router.get("/{identifier}/report")
async def export_incident_report(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> Response:
    """Build a markdown report for an incident."""
    incident = None
    try:
        uuid_value = UUID(identifier)
        incident = incident_service.get_incident_detail(user.organization_id, uuid_value)
    except ValueError:
        incident = incident_service.get_incident_by_short_id(user.organization_id, identifier)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found",
        )

    threats = incident_service.list_threats_for_incident(
        user.organization_id,
        UUID(incident["id"]),
    )

    admin = get_supabase_admin()
    audit_rows = (
        admin.table("audit_logs")
        .select("created_at, actor_type, actor_name, action, severity, reason")
        .eq("organization_id", user.organization_id)
        .eq("target_id", incident["id"])
        .order("created_at", desc=False)
        .limit(50)
        .execute()
    ).data or []

    approvals: list[dict[str, Any]] = []
    try:
        approvals = (
            admin.table("playbook_approvals")
            .select("playbook_name, action_type, target, priority, status, decided_by_name, decision_note, created_at")
            .eq("organization_id", user.organization_id)
            .eq("incident_id", incident["id"])
            .order("created_at", desc=False)
            .limit(25)
            .execute()
        ).data or []
    except Exception:
        approvals = []

    short_id = incident.get("short_id", "INCIDENT")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    attribution = incident.get("attribution") or {}

    lines: list[str] = [
        f"# Incident Report: {short_id}",
        "",
        f"**{incident.get('title', 'Untitled incident')}**",
        "",
        f"- Generated: {generated_at}",
        f"- Generated by: {user.full_name or user.email} ({user.role})",
        f"- Severity: {incident.get('severity', 'unknown')} · Status: {incident.get('status', 'unknown')} · Priority: {incident.get('priority', 'n/a')}",
        f"- Confidence: {incident.get('confidence', 'n/a')} · Risk score: {incident.get('risk_score', 'n/a')}",
        f"- First seen: {incident.get('first_seen_at', 'n/a')} · Last seen: {incident.get('last_seen_at', 'n/a')}",
        "",
        "## Summary",
        "",
        incident.get("description") or "No description recorded.",
        "",
        "## Attribution",
        "",
        f"- Actor: {attribution.get('actor', 'unknown')}",
    ]
    if attribution.get("alias"):
        lines.append(f"- Alias: {attribution['alias']}")
    if attribution.get("campaign"):
        lines.append(f"- Campaign: {attribution['campaign']}")
    lines += [
        f"- Source IPs: {_md_list(incident.get('source_ips'))}",
        f"- MITRE tactics: {_md_list(incident.get('mitre_tactics'))}",
        f"- MITRE techniques: {_md_list(incident.get('mitre_techniques'))}",
        f"- Tags: {_md_list(incident.get('tags'))}",
        "",
        f"## Linked threats ({len(threats)})",
        "",
    ]
    if threats:
        for t in threats:
            lines.append(
                f"- **{t.get('short_id', '?')}** [{t.get('severity', '?')}/{t.get('status', '?')}] "
                f"{t.get('title', 'Untitled threat')}"
            )
    else:
        lines.append("- No linked threats.")

    lines += ["", f"## Response authorizations ({len(approvals)})", ""]
    if approvals:
        for a in approvals:
            decided = (
                f"{a['status']}"
                + (f" by {a['decided_by_name']}" if a.get("decided_by_name") else "")
            )
            lines.append(
                f"- {a.get('playbook_name')} ({a.get('action_type')}) on `{a.get('target')}` "
                f"· priority {a.get('priority')} · **{decided}**"
            )
    else:
        lines.append("- No response actions recorded for this incident.")

    lines += ["", f"## Chain of custody ({len(audit_rows)} audit events)", ""]
    if audit_rows:
        for row in audit_rows:
            actor = row.get("actor_name") or row.get("actor_type", "system")
            lines.append(
                f"- `{row.get('created_at', '')}` · {row.get('action', '')} "
                f"· {actor} [{row.get('severity', 'info')}]"
                + (f" · {row['reason']}" if row.get("reason") else "")
            )
    else:
        lines.append("- No audit events recorded for this incident.")

    lines += [
        "",
        "---",
        "",
        "_This report was generated by ThreatBrain from the append-only audit trail. "
        "Audit records cannot be modified or deleted at the database level._",
        "",
    ]

    markdown = "\n".join(lines)
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{short_id}-report.md"',
        },
    )