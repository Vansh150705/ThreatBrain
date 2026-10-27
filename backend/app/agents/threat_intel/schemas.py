from __future__ import annotations

import ipaddress
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import SeverityLevel

class ThreatIntelInput(BaseModel):
    """An IP address to enrich.

    Looked up against every configured feed (AbuseIPDB, VirusTotal, OTX).
    """

    ip_address: str = Field(..., min_length=3, max_length=45)
    context: str | None = Field(
        default=None,
        description="Optional surrounding context to help the LLM reason.",
        max_length=2000,
    )

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {v!r}") from exc


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

    # Cross-feed facts attached server-side
    composite_score: int | None = Field(default=None, ge=0, le=100)
    feed_scores: dict[str, int] = Field(default_factory=dict)
    feeds_used: list[str] = Field(default_factory=list)
    feed_errors: dict[str, str] = Field(default_factory=dict)
    internal: bool = False

    tags: list[str] = Field(default_factory=list)
    raw_feeds: dict[str, Any] = Field(default_factory=dict)

    @field_validator("reputation", mode="before")
    @classmethod
    def _normalize_reputation(cls, v: Any) -> str:
        v = str(v).lower().strip()
        # Small models sometimes answer "clean" / "high risk"; map instead of failing the stage.
        aliases = {"clean": "benign", "safe": "benign", "bad": "malicious", "high": "malicious"}
        v = aliases.get(v, v)
        return v if v in {"benign", "unknown", "suspicious", "malicious"} else "unknown"


__all__ = ["ThreatIntelInput", "ThreatIntelOutput"]