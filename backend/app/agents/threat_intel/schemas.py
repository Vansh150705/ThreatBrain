from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import SeverityLevel

class ThreatIntelInput(BaseModel):
    """An IP address to enrich.

    For now we only support IPs. VirusTotal/hash lookups, Shodan,
    and OTX will extend this in later steps.
    """

    ip_address: str = Field(..., min_length=3, max_length=45)
    context: str | None = Field(
        default=None,
        description="Optional surrounding context to help the LLM reason.",
        max_length=2000,
    )


class ThreatIntelOutput(BaseModel):
    """The Threat Intel Agent's enrichment verdict."""

    ip_address: str
    reputation: str = Field(..., description="benign | unknown | suspicious | malicious")
    confidence: int = Field(..., ge=0, le=100)
    threat_score: int = Field(..., ge=0, le=100)
    severity: SeverityLevel
    summary: str = Field(..., min_length=1)
    reasoning: str = Field(..., min_length=1)

    # Geo / network
    country_code: str | None = None
    isp: str | None = None
    usage_type: str | None = None

    # Raw enrichment cached for downstream agents
    abuse_score: int = Field(default=0, ge=0, le=100)
    total_reports: int = Field(default=0, ge=0)
    last_reported_at: str | None = None

    tags: list[str] = Field(default_factory=list)
    raw_feeds: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reputation")
    @classmethod
    def _normalize_reputation(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"benign", "unknown", "suspicious", "malicious"}:
            raise ValueError(
                f"reputation must be benign|unknown|suspicious|malicious, got '{v}'"
            )
        return v


__all__ = ["ThreatIntelInput", "ThreatIntelOutput"]