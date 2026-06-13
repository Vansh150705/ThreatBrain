from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import SeverityLevel

class TriageInput(BaseModel):
    """The security event the Triage Agent should classify."""

    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    source: str = Field(
        default="manual",
        description="edr | firewall | cloud_audit | siem | dns | application | authentication | email | manual | simulator | other",
    )
    event_type: str = Field(
        default="generic.event",
        description="Dotted category like 'authentication.failed'.",
    )

    # Network context
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    # Identity / process / file context
    username: str | None = None
    process_name: str | None = None
    command_line: str | None = Field(default=None, max_length=8000)
    file_hash: str | None = None

    # Asset context (helps the agent calibrate severity)
    asset_name: str | None = None
    asset_type: str | None = None
    asset_environment: str | None = None
    asset_criticality: str | None = Field(
        default=None, description="low | medium | high | crown_jewel"
    )

    # whatever else the source sent
    raw_data: dict[str, Any] = Field(default_factory=dict)


class TriageOutput(BaseModel):
    """The Triage Agent's classification verdict."""

    severity: SeverityLevel
    confidence: int = Field(..., ge=0, le=100)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(..., min_length=1)
    reasoning: str = Field(..., min_length=1)

    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE tactic IDs (e.g., ['TA0001','TA0006']).",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE technique IDs (e.g., ['T1110','T1110.001']).",
    )

    tags: list[str] = Field(default_factory=list)
    promote_to_threat: bool = Field(
        default=False,
        description="True if this should be created as a threat row.",
    )

    @field_validator("mitre_tactics", "mitre_techniques")
    @classmethod
    def _strip_empties(cls, v: list[str]) -> list[str]:
        return [s.strip() for s in v if s and s.strip()]


__all__ = ["TriageInput", "TriageOutput"]