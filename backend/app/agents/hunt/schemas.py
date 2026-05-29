from __future__ import annotations

from pydantic import BaseModel, Field

class HuntInput(BaseModel):
    """Optional focus areas for the hunt; otherwise the agent
    generates hypotheses from full recent context."""

    lookback_hours: int = Field(
        default=168,
        ge=1,
        le=720,
        description="How far back to consider (default 7 days).",
    )
    focus_areas: list[str] = Field(
        default_factory=list,
        description=(
            "Optional focus like 'lateral_movement', 'persistence', "
            "'data_exfiltration'. Empty = no preset focus."
        ),
    )
    max_hypotheses: int = Field(default=5, ge=1, le=15)

class HuntHypothesis(BaseModel):
    """One testable hunting theory."""

    title: str = Field(..., min_length=1, max_length=200)
    hypothesis: str = Field(
        ...,
        min_length=1,
        description="The full hypothesis statement in plain English.",
    )
    likelihood: str = Field(
        ...,
        description='"low" | "medium" | "high" — how plausible this is.',
    )
    confidence: int = Field(..., ge=0, le=100)
    mitre_techniques: list[str] = Field(default_factory=list)
    suggested_query: str = Field(
        ...,
        description="A SQL-like query or log search the analyst can run.",
    )
    expected_evidence: list[str] = Field(
        default_factory=list,
        description="What signals would confirm the hypothesis.",
    )
    rationale: str = Field(..., min_length=1)


class HuntOutput(BaseModel):
    """All hypotheses the Hunt Agent generated this run."""

    summary: str = Field(..., min_length=1)
    hypotheses: list[HuntHypothesis] = Field(default_factory=list)
    threats_considered: int = Field(default=0, ge=0)
    iocs_considered: int = Field(default=0, ge=0)
    assets_considered: int = Field(default=0, ge=0)


__all__ = ["HuntInput", "HuntOutput", "HuntHypothesis"]