from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import SeverityLevel


class ResponseInput(BaseModel):
    """Which incident to respond to and how aggressive to be."""

    incident_short_id: str = Field(
        ...,
        description="short_id of the incident to act on (e.g., 'INC-ACT001').",
    )
    dry_run: bool = Field(
        default=True,
        description="If True, simulate actions; nothing actually changes.",
    )
    execute_auto_playbooks: bool = Field(
        default=False,
        description=(
            "Deprecated and ignored: the server never executes actions itself. "
            "Approved actions are carried out by tb-executor on the target host."
        ),
    )


class ActionRecommendation(BaseModel):
    """One recommended (or executed) response action."""

    playbook_name: str
    action_type: str = Field(
        ...,
        description="block_ip | disable_user | isolate_host | notify | quarantine_email | revoke_token | other",
    )
    target: str = Field(
        ...,
        description="What this action targets (IP, user, host, etc.).",
    )
    priority: int = Field(..., ge=1, le=10)
    rationale: str = ""
    status: str = Field(
        default="recommended",
        description=(
            "recommended (queued for human approval) | simulated (dry run, nothing "
            "queued) | skipped (rejected by a safety check; see skip_reason). "
            "'executed' only ever appears via the approval queue after tb-executor reports."
        ),
    )
    skip_reason: str | None = None


class ResponseOutput(BaseModel):
    """The Response Agent's plan + execution log."""

    incident_short_id: str
    overall_severity: SeverityLevel
    summary: str
    actions: list[ActionRecommendation] = Field(default_factory=list)
    skipped_count: int = Field(default=0, ge=0)
    executed_count: int = Field(default=0, ge=0)
    simulated_count: int = Field(default=0, ge=0)
    recommended_count: int = Field(default=0, ge=0)


__all__ = ["ResponseInput", "ResponseOutput", "ActionRecommendation"]