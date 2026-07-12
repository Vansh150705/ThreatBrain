"""Playbook approval queue. Admins approve or reject what the response agent recommends."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, get_current_user, require_admin, require_analyst
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


class ApprovalItem(BaseModel):
    id: str
    incident_id: Optional[str] = None
    incident_short_id: Optional[str] = None
    incident_title: Optional[str] = None
    playbook_name: str
    action_type: str
    target: str
    priority: int
    rationale: Optional[str] = None
    status: str
    requested_by: Optional[str] = None
    decided_by_name: Optional[str] = None
    decision_note: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime
    execution_status: Optional[str] = None
    executed_at: Optional[datetime] = None
    execution_detail: Optional[str] = None


class ApprovalListResponse(BaseModel):
    items: list[ApprovalItem]
    total: int


class DecisionRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    note: Optional[str] = Field(default=None, max_length=500)


class ExecutionReport(BaseModel):
    result: Literal["executed", "failed"]
    detail: Optional[str] = Field(default=None, max_length=1000)


@router.get("/approvals", response_model=ApprovalListResponse)
async def list_approvals(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    approval_status: Optional[str] = Query(default=None, alias="status"),
    action_type: Optional[str] = Query(default=None),
    pending_execution: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
) -> ApprovalListResponse:
    """List the approval queue for the user's org, newest first.

    Executor filters: ``action_type`` narrows to one action (e.g. block_ip);
    ``pending_execution=true`` returns only approved actions not yet executed.
    """
    admin = get_supabase_admin()
    query = (
        admin.table("playbook_approvals")
        .select("*", count="exact")
        .eq("organization_id", user.organization_id)
    )
    if pending_execution:
        query = query.eq("status", "approved").is_("execution_status", "null")
    elif approval_status:
        query = query.eq("status", approval_status)
    if action_type:
        query = query.eq("action_type", action_type)

    result = query.order("created_at", desc=True).limit(limit).execute()
    rows = result.data or []
    return ApprovalListResponse(
        items=[ApprovalItem.model_validate(r) for r in rows],
        total=result.count or 0,
    )


@router.post("/approvals/{approval_id}/decision", response_model=ApprovalItem)
async def decide_approval(
    approval_id: str,
    request: DecisionRequest,
    user: Annotated[CurrentUser, Depends(require_admin)],
) -> ApprovalItem:
    """Approve or reject one pending recommendation. Admin or owner only."""
    admin = get_supabase_admin()

    rows = (
        admin.table("playbook_approvals")
        .select("*")
        .eq("id", approval_id)
        .eq("organization_id", user.organization_id)
        .limit(1)
        .execute()
    ).data or []
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found.")
    approval = rows[0]
    if approval["status"] != "pending":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This recommendation was already {approval['status']}.",
        )

    updated = (
        admin.table("playbook_approvals")
        .update(
            {
                "status": request.decision,
                "decided_by": user.id,
                "decided_by_name": user.full_name or user.email,
                "decision_note": request.note,
                "decided_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        .eq("id", approval_id)
        .execute()
    ).data[0]

    # log the decision to the audit trail
    try:
        admin.table("audit_logs").insert(
            {
                "organization_id": user.organization_id,
                "actor_type": "user",
                "actor_id": user.id,
                "actor_email": user.email,
                "actor_name": user.full_name or user.email,
                "action": f"playbook.{request.decision}",
                "target_type": "incident",
                "target_id": approval.get("incident_id"),
                "target_short_id": approval.get("incident_short_id"),
                "target_name": approval.get("incident_title"),
                "severity": "high" if request.decision == "approved" else "info",
                "reason": request.note
                or f"{approval['playbook_name']} on {approval['target']} {request.decision} by {user.role}.",
                "changes": {
                    "playbook_name": approval["playbook_name"],
                    "action_type": approval["action_type"],
                    "target": approval["target"],
                    "status": {"from": "pending", "to": request.decision},
                },
            }
        ).execute()
    except Exception:
        log.exception("approval_audit_log_failed")

    log.info(
        "playbook_approval_decided",
        approval_id=approval_id,
        decision=request.decision,
        decided_by=user.id,
    )
    return ApprovalItem.model_validate(updated)


@router.post("/approvals/{approval_id}/execution", response_model=ApprovalItem)
async def report_execution(
    approval_id: str,
    request: ExecutionReport,
    user: Annotated[CurrentUser, Depends(require_analyst)],
) -> ApprovalItem:
    """Record the real-world execution result of an approved action.

    Called by tb-executor after it runs (or fails to run) the block on the host.
    """
    admin = get_supabase_admin()

    rows = (
        admin.table("playbook_approvals")
        .select("*")
        .eq("id", approval_id)
        .eq("organization_id", user.organization_id)
        .limit(1)
        .execute()
    ).data or []
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found.")
    approval = rows[0]

    if approval["status"] != "approved":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only approved actions can be executed; this one is {approval['status']}.",
        )
    if approval.get("execution_status") is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This action was already {approval['execution_status']}.",
        )

    updated = (
        admin.table("playbook_approvals")
        .update(
            {
                "execution_status": request.result,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "execution_detail": request.detail,
            }
        )
        .eq("id", approval_id)
        .execute()
    ).data[0]

    # log the real-world action to the append-only audit trail
    try:
        admin.table("audit_logs").insert(
            {
                "organization_id": user.organization_id,
                "actor_type": "system",
                "actor_name": "tb-executor",
                "action": f"response.block_ip.{request.result}",
                "target_type": "incident",
                "target_id": approval.get("incident_id"),
                "target_short_id": approval.get("incident_short_id"),
                "target_name": approval.get("incident_title"),
                "severity": "high" if request.result == "executed" else "info",
                "status": "success" if request.result == "executed" else "failure",
                "reason": request.detail
                or f"{approval['playbook_name']} on {approval['target']} {request.result}.",
                "metadata": {
                    "action_type": approval["action_type"],
                    "target": approval["target"],
                    "execution_status": request.result,
                },
            }
        ).execute()
    except Exception:
        log.exception("execution_audit_log_failed")

    log.info(
        "playbook_execution_reported",
        approval_id=approval_id,
        result=request.result,
    )
    return ApprovalItem.model_validate(updated)
