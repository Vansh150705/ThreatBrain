from __future__ import annotations

from pydantic import BaseModel, Field

class ComplianceInput(BaseModel):
    """Which incident to assess and which regulations to consider."""

    incident_short_id: str = Field(..., min_length=3, max_length=40)
    regulations: list[str] = Field(
        default_factory=lambda: ["GDPR", "HIPAA", "PCI-DSS", "SOC2", "ISO27001"],
        description="Subset of regulations to assess; default is all common ones.",
    )


class RegulationReport(BaseModel):
    """A compliance assessment under one regulation."""

    regulation: str = Field(
        ..., description="GDPR | HIPAA | PCI-DSS | SOC2 | ISO27001 | other"
    )
    applies: bool = Field(
        ..., description="True if this regulation likely applies to the incident."
    )
    reason: str = Field(..., description="Why this regulation applies (or doesn't).")
    notification_required: bool = Field(default=False)
    notification_deadline_hours: int | None = Field(
        default=None,
        description="Hours from incident detection until notification is required.",
    )
    affected_data_categories: list[str] = Field(
        default_factory=list,
        description="e.g., ['personal_data', 'payment_data', 'health_data']",
    )
    estimated_affected_records: int | None = Field(default=None, ge=0)
    risk_to_data_subjects: str = Field(
        default="unknown",
        description="low | medium | high | severe | unknown",
    )
    mitigations_in_place: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)
    notification_template: str | None = Field(
        default=None,
        description="Draft text for the required notification (≤500 chars).",
    )


class ComplianceOutput(BaseModel):
    """Compliance Agent's full assessment of an incident."""

    incident_short_id: str
    overall_compliance_risk: str = Field(
        ..., description="low | medium | high | critical"
    )
    executive_summary: str = Field(..., min_length=1)
    applicable_regulations: list[str] = Field(default_factory=list)
    mandatory_deadlines: list[str] = Field(
        default_factory=list,
        description="Plain-English deadline reminders like 'GDPR Art. 33 — 72 hours from detection'.",
    )
    reports: list[RegulationReport] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)


__all__ = ["ComplianceInput", "ComplianceOutput", "RegulationReport"]