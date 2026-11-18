from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.common import SeverityLevel

MAX_LINES = 300
MAX_LINE_CHARS = 2000


class LogAnalysisInput(BaseModel):
    """Raw log lines to analyse (paste of auth.log, web access log, CloudTrail JSON lines...)."""

    lines: list[str] = Field(default_factory=list, max_length=MAX_LINES)
    text: str | None = Field(default=None, max_length=MAX_LINES * 200)
    source_hint: str | None = Field(
        default=None, max_length=100, description="e.g. 'sshd auth.log', 'nginx access', 'windows security'."
    )

    @model_validator(mode="after")
    def _normalise(self) -> "LogAnalysisInput":
        lines = list(self.lines)
        if self.text:
            lines.extend(self.text.splitlines())
        cleaned = [ln.rstrip()[:MAX_LINE_CHARS] for ln in lines if ln.strip()]
        if not cleaned:
            raise ValueError("provide at least one non-empty log line")
        if len(cleaned) > MAX_LINES:
            raise ValueError(f"too many lines (max {MAX_LINES})")
        self.lines, self.text = cleaned, None
        return self


class Entities(BaseModel):
    ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)

    @field_validator("*", mode="before")
    @classmethod
    def _as_str_list(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(x).strip() for x in v if str(x).strip()][:50]


class Finding(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    detail: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    evidence_lines: list[int] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    verified: bool = Field(
        default=False,
        description="True when every cited line number exists in the submitted log.",
    )

    @field_validator("evidence_lines", mode="before")
    @classmethod
    def _ints(cls, v: Any) -> list[int]:
        out: list[int] = []
        for x in v if isinstance(v, list) else []:
            try:
                out.append(int(x))
            except (TypeError, ValueError):
                continue
        return out[:50]

    @field_validator("severity", mode="before")
    @classmethod
    def _sev(cls, v: Any) -> Any:
        v = str(v).lower().strip()
        return v if v in {"info", "low", "medium", "high", "critical"} else "medium"


class LogAnalysisOutput(BaseModel):
    summary: str = Field(..., min_length=1)
    severity: SeverityLevel
    confidence: int = Field(..., ge=0, le=100)
    entities: Entities = Field(default_factory=Entities)
    findings: list[Finding] = Field(default_factory=list)
    suggested_detections: list[str] = Field(default_factory=list)
    reasoning: str = ""
    rule_hits: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Deterministic rule matches per line, attached server-side.",
    )
    lines_analyzed: int = 0


__all__ = ["LogAnalysisInput", "LogAnalysisOutput", "Finding", "Entities"]
