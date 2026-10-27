"""Case management: incident/threat lifecycle, assignment, notes and evidence timeline."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.api.deps import CurrentUser
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

STATUSES = ("open", "investigating", "contained", "resolved", "closed", "false_positive")
PRIORITIES = ("p1", "p2", "p3", "p4")
_CLOSED = {"resolved", "closed", "false_positive"}
_REOPENED = {"open", "investigating"}


class CaseError(ValueError):
    """A change that violates case-management rules (maps to HTTP 400/404)."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def audit(
    user: CurrentUser,
    *,
    action: str,
    target_type: str,
    row: dict[str, Any],
    changes: dict[str, Any],
    reason: str | None = None,
    severity: str = "info",
) -> None:
    """Append to the immutable audit trail. Failure to audit is logged loudly."""
    try:
        get_supabase_admin().table("audit_logs").insert(
            {
                "organization_id": user.organization_id,
                "actor_type": "user" if user.auth_method == "jwt" else "api",
                "actor_id": user.id,
                "actor_email": user.email,
                "actor_name": user.display_name,
                "action": action,
                "target_type": target_type,
                "target_id": row.get("id"),
                "target_short_id": row.get("short_id"),
                "target_name": row.get("title"),
                "severity": severity,
                "reason": reason,
                "changes": changes,
            }
        ).execute()
    except Exception:
        log.exception("audit_write_failed", action=action)


def _validate_assignee(org_id: str, assignee: str | None) -> None:
    if assignee is None:
        return
    rows = (
        get_supabase_admin()
        .table("users")
        .select("id, status, role")
        .eq("organization_id", org_id)
        .eq("id", assignee)
        .is_("deleted_at", "null")
        .limit(1)
        .execute()
        .data
        or []
    )
    if not rows or rows[0].get("status") == "disabled":
        raise CaseError("assigned_to must be an active member of your organization")
    if rows[0].get("role") == "viewer":
        raise CaseError("viewers cannot own cases; assign an analyst or admin")


def list_members(org_id: str) -> list[dict[str, Any]]:
    return (
        get_supabase_admin()
        .table("users")
        .select("id, full_name, email, role, status")
        .eq("organization_id", org_id)
        .is_("deleted_at", "null")
        .order("full_name")
        .execute()
        .data
        or []
    )


def update_incident(user: CurrentUser, incident: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    """Apply status / priority / assignee changes with lifecycle timestamps + audit."""
    org = str(user.organization_id)
    patch: dict[str, Any] = {}
    diff: dict[str, Any] = {}

    if "priority" in changes and changes["priority"] != incident.get("priority"):
        if changes["priority"] not in PRIORITIES:
            raise CaseError(f"priority must be one of {', '.join(PRIORITIES)}")
        patch["priority"] = changes["priority"]
        diff["priority"] = {"from": incident.get("priority"), "to": changes["priority"]}

    if "assigned_to" in changes and changes["assigned_to"] != incident.get("assigned_to"):
        _validate_assignee(org, changes["assigned_to"])
        patch["assigned_to"] = changes["assigned_to"]
        diff["assigned_to"] = {"from": incident.get("assigned_to"), "to": changes["assigned_to"]}

    new_status = changes.get("status")
    if new_status is not None and new_status != incident.get("status"):
        if new_status not in STATUSES:
            raise CaseError(f"status must be one of {', '.join(STATUSES)}")
        patch["status"] = new_status
        diff["status"] = {"from": incident.get("status"), "to": new_status}
        now = _now()
        first_seen = str(incident.get("first_seen_at") or now)
        stamp = max(now, first_seen)  # table constraint: lifecycle stamps >= first_seen_at
        if new_status == "contained" and not incident.get("contained_at"):
            patch["contained_at"] = stamp
        if new_status in _CLOSED:
            patch["resolved_at"] = stamp
            if not incident.get("contained_at"):
                patch["contained_at"] = stamp
        if new_status in _REOPENED:
            patch["resolved_at"] = None

    if not patch:
        return incident

    client = get_supabase_admin()
    rows = (
        client.table("incidents")
        .update(patch)
        .eq("organization_id", org)
        .eq("id", incident["id"])
        .execute()
        .data
        or []
    )
    if not rows:
        raise CaseError("incident no longer exists")
    updated = rows[0]

    # Closing a case closes its open threats, so dashboards and de-dup stay truthful.
    if new_status in _CLOSED:
        threat_status = "false_positive" if new_status == "false_positive" else "resolved"
        client.table("threats").update(
            {"status": threat_status, "resolved_at": patch["resolved_at"]}
        ).eq("organization_id", org).eq("incident_id", incident["id"]).in_(
            "status", ["open", "investigating", "contained"]
        ).execute()

    action = "incident.status_changed" if "status" in diff else "incident.updated"
    audit(user, action=action, target_type="incident", row=updated, changes=diff,
          severity="high" if new_status == "false_positive" else "info")
    return updated


def update_threat(user: CurrentUser, threat: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    org = str(user.organization_id)
    patch: dict[str, Any] = {}
    diff: dict[str, Any] = {}
    new_status = changes.get("status")
    if new_status is not None and new_status != threat.get("status"):
        if new_status not in STATUSES:
            raise CaseError(f"status must be one of {', '.join(STATUSES)}")
        patch["status"] = new_status
        diff["status"] = {"from": threat.get("status"), "to": new_status}
        if new_status in _CLOSED:
            patch["resolved_at"] = max(_now(), str(threat.get("detected_at") or ""))
        elif new_status in _REOPENED:
            patch["resolved_at"] = None
    if "assigned_to" in changes and changes["assigned_to"] != threat.get("assigned_to"):
        _validate_assignee(org, changes["assigned_to"])
        patch["assigned_to"] = changes["assigned_to"]
        diff["assigned_to"] = {"from": threat.get("assigned_to"), "to": changes["assigned_to"]}
    if not patch:
        return threat
    rows = (
        get_supabase_admin().table("threats").update(patch)
        .eq("organization_id", org).eq("id", threat["id"]).execute().data or []
    )
    if not rows:
        raise CaseError("threat no longer exists")
    audit(user, action="threat.status_changed" if "status" in diff else "threat.updated",
          target_type="threat", row=rows[0], changes=diff)
    return rows[0]


# --------------------------------------------------------------- notes ----
def add_note(user: CurrentUser, incident: dict[str, Any], body: str) -> dict[str, Any]:
    body = body.strip()
    if not body:
        raise CaseError("note must not be empty")
    row = (
        get_supabase_admin()
        .table("incident_notes")
        .insert(
            {
                "organization_id": user.organization_id,
                "incident_id": incident["id"],
                "author_id": user.id if user.auth_method == "jwt" else None,
                "author_name": user.display_name,
                "body": body[:5000],
            }
        )
        .execute()
        .data[0]
    )
    audit(user, action="incident.note_added", target_type="incident", row=incident,
          changes={"note_id": row["id"], "length": len(body)})
    return row


def list_notes(org_id: str, incident_id: str) -> list[dict[str, Any]]:
    return (
        get_supabase_admin()
        .table("incident_notes")
        .select("id, author_id, author_name, body, created_at")
        .eq("organization_id", org_id)
        .eq("incident_id", incident_id)
        .order("created_at", desc=False)
        .limit(500)
        .execute()
        .data
        or []
    )


# ------------------------------------------------------------ timeline ----
def build_timeline(org_id: str, incident: dict[str, Any]) -> list[dict[str, Any]]:
    """One chronological evidence trail: threats, agent/human actions, notes, approvals."""
    client = get_supabase_admin()
    iid = incident["id"]
    events: list[dict[str, Any]] = []

    for t in (
        client.table("threats")
        .select("short_id, title, severity, detected_at, event_count, source_ips")
        .eq("organization_id", org_id).eq("incident_id", iid).is_("deleted_at", "null").execute().data or []
    ):
        extra = f" ({t['event_count']} events)" if int(t.get("event_count") or 1) > 1 else ""
        events.append({
            "ts": t["detected_at"], "kind": "threat", "severity": t["severity"],
            "title": f"{t['short_id']} detected{extra}", "detail": t["title"], "actor": "detection",
        })

    for a in (
        client.table("audit_logs")
        .select("created_at, actor_type, actor_name, action, severity, reason")
        .eq("organization_id", org_id).eq("target_id", iid).order("created_at").limit(200).execute().data or []
    ):
        events.append({
            "ts": a["created_at"], "kind": "audit", "severity": a.get("severity") or "info",
            "title": a["action"], "detail": a.get("reason"), "actor": a.get("actor_name") or a.get("actor_type"),
        })

    for n in list_notes(org_id, iid):
        events.append({
            "ts": n["created_at"], "kind": "note", "severity": "info",
            "title": "Analyst note", "detail": n["body"], "actor": n.get("author_name"),
        })

    for ev in incident.get("timeline") or []:
        if isinstance(ev, dict) and ev.get("ts"):
            events.append({
                "ts": ev["ts"], "kind": "forensics", "severity": "info",
                "title": f"{ev.get('phase') or 'activity'}", "detail": ev.get("event"),
                "actor": ev.get("actor") or "forensics_agent",
            })

    events.sort(key=lambda e: str(e["ts"]))
    return events
