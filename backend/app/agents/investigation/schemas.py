from __future__ import annotations

from pydantic import BaseModel, Field

from app.schemas.common import SeverityLevel


class InvestigationInput(BaseModel):
    """How far back to look for threats to correlate."""

    lookback_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="How many hours of recent threats to consider.",
    )
    max_threats: int = Field(
        default=30,
        ge=2,
        le=100,
        description="Cap on the number of threats sent to the LLM.",
    )
    min_severity: str = Field(
        default="low",
        description="Skip threats below this severity (info|low|medium|high|critical).",
    )


class ThreatGroup(BaseModel):
    """One correlated cluster — becomes an incident."""

    title: str = Field(..., min_length=1, max_length=300)
    summary: str = Field(..., min_length=1)
    severity: SeverityLevel
    confidence: int = Field(..., ge=0, le=100)
    threat_short_ids: list[str] = Field(
        ...,
        min_length=1,
        description="short_id values of threats in this group (e.g. ['THR-A1B2', 'THR-C3D4']).",
    )
    kill_chain_phase: str | None = Field(
        default=None,
        description="reconnaissance|weaponization|delivery|exploitation|installation|command_and_control|actions_on_objectives",
    )
    attribution_hint: str | None = Field(
        default=None,
        description="Free-form attribution guess like 'likely automated scanner' or 'targeted APT-style behavior'.",
    )
    reasoning: str = Field(..., min_length=1)


class InvestigationOutput(BaseModel):
    """The Investigation Agent's verdict."""

    groups: list[ThreatGroup] = Field(default_factory=list)
    unrelated_threat_short_ids: list[str] = Field(
        default_factory=list,
        description="Threats that don't fit any group.",
    )
    summary: str = Field(..., min_length=1)


__all__ = ["InvestigationInput", "InvestigationOutput", "ThreatGroup"]