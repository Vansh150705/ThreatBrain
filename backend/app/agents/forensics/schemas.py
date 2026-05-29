from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import SeverityLevel


class ForensicsInput(BaseModel):
    """Which incident to reconstruct a timeline for."""

    incident_short_id: str = Field(..., min_length=3, max_length=40)

class TimelineEvent(BaseModel):
    """One step in the reconstructed attack timeline."""

    timestamp: str = Field(
        ..., description="ISO-8601 timestamp, copy from the threat's detected_at."
    )
    threat_short_id: str | None = Field(
        default=None, description="The threat referenced here, if any."
    )
    phase: str = Field(
        ...,
        description=(
            "reconnaissance | initial_access | execution | persistence | "
            "privilege_escalation | defense_evasion | credential_access | "
            "discovery | lateral_movement | collection | command_and_control | "
            "exfiltration | impact"
        ),
    )
    actor: str | None = Field(
        default=None, description="Who/what did this (IP, user, process)."
    )
    target: str | None = Field(default=None, description="What was targeted.")
    description: str = Field(..., min_length=1)
    artifacts: list[str] = Field(
        default_factory=list,
        description="Concrete artifacts: hashes, IPs, file paths, registry keys.",
    )


class ForensicsOutput(BaseModel):
    """The full forensic reconstruction of an incident."""

    incident_short_id: str
    overall_severity: SeverityLevel
    executive_summary: str = Field(..., min_length=1)
    attack_narrative: str = Field(
        ...,
        min_length=1,
        description="3-5 paragraph investigator-style story.",
    )
    timeline: list[TimelineEvent] = Field(default_factory=list)
    key_artifacts: list[str] = Field(
        default_factory=list,
        description="Top 5-10 IOCs / files / accounts to preserve as evidence.",
    )
    evidence_recommendations: list[str] = Field(
        default_factory=list,
        description="What to preserve / collect (logs, memory dumps, etc.).",
    )
    affected_assets: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)


__all__ = ["ForensicsInput", "ForensicsOutput", "TimelineEvent"]