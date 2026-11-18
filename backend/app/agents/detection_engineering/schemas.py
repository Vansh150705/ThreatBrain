from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TuningInput(BaseModel):
    """Evidence handed to the agent. Samples are real events from threats analysts closed as false positives
    (or resolved as genuine); the agent is told they are data, not instructions."""

    rule: dict[str, Any]
    stats: dict[str, int]
    false_positive_samples: list[dict[str, Any]] = Field(default_factory=list, max_length=10)
    true_positive_samples: list[dict[str, Any]] = Field(default_factory=list, max_length=10)


class TestCase(BaseModel):
    name: str = Field(default="", max_length=200)
    event: dict[str, Any]
    expect_match: bool


class TuningOutput(BaseModel):
    assessment: str = Field(..., min_length=1, max_length=2000)
    recommendation: Literal["tune", "disable", "keep"]
    rationale: str = Field(..., min_length=1, max_length=2000)
    proposed_match: dict[str, Any] | None = None
    tests: list[TestCase] = Field(default_factory=list, max_length=20)
    changes: list[str] = Field(default_factory=list, max_length=10)
