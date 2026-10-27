from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import SeverityLevel

_MITRE_ID = re.compile(r"^(TA\d{4}|T\d{4}(\.\d{3})?)$")


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

    # When the event happened at the source (falls back to ingest time)
    occurred_at: datetime | None = None

    # whatever else the source sent
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        """Addresses end up in INET columns and feed lookups; reject junk early."""
        if v is None or not v.strip():
            return None
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {v!r}") from exc

    @field_validator("title")
    @classmethod
    def _strip_title(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title must not be blank")
        return v

    @field_validator("username", "process_name", "asset_name", "asset_type", "asset_environment")
    @classmethod
    def _bound_short_text(cls, v: str | None) -> str | None:
        return v.strip()[:256] if isinstance(v, str) and v.strip() else None

    @field_validator("description")
    @classmethod
    def _bound_description(cls, v: str | None) -> str | None:
        return v[:4000] if isinstance(v, str) else v

    @field_validator("file_hash")
    @classmethod
    def _valid_hash(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip().lower()
        if len(v) not in (32, 40, 64) or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("file_hash must be an MD5, SHA-1 or SHA-256 hex digest")
        return v

    @field_validator("asset_criticality")
    @classmethod
    def _valid_criticality(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if v == "critical":  # common synonym
            v = "crown_jewel"
        if v not in {"low", "medium", "high", "crown_jewel"}:
            raise ValueError("asset_criticality must be low | medium | high | crown_jewel")
        return v

    @field_validator("raw_data")
    @classmethod
    def _bound_raw(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v, default=str)) > 60_000:
            raise ValueError("raw_data is too large (max 60 KB)")
        return v


class EvidenceItem(BaseModel):
    """One fact backing a verdict, with where it came from."""

    source: str = Field(default="event", description="event | rule:<id> | threat_intel | log | llm")
    detail: str


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

    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="Facts from the event/rule hits that justify the verdict.",
    )
    tags: list[str] = Field(default_factory=list)
    promote_to_threat: bool = Field(
        default=False,
        description="True if this should be created as a threat row.",
    )

    @field_validator("mitre_tactics", "mitre_techniques", mode="before")
    @classmethod
    def _clean_mitre(cls, v: Any) -> list[str]:
        """Keep only well-formed ATT&CK IDs (TA0001 / T1110 / T1110.001)."""
        if not isinstance(v, list):
            return []
        out: list[str] = []
        for item in v:
            token = str(item).strip().upper()
            if _MITRE_ID.match(token) and token not in out:
                out.append(token)
        return out

    @field_validator("evidence", mode="before")
    @classmethod
    def _coerce_evidence(cls, v: Any) -> Any:
        if not isinstance(v, list):
            return []
        out: list[Any] = []
        for item in v:
            if isinstance(item, str) and item.strip():
                out.append({"source": "llm", "detail": item.strip()})
            elif isinstance(item, dict) and (item.get("detail") or item.get("description")):
                out.append(
                    {
                        "source": str(item.get("source") or "llm"),
                        "detail": str(item.get("detail") or item.get("description")),
                    }
                )
        return out[:20]

    @field_validator("tags", mode="before")
    @classmethod
    def _clean_tags(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            return []
        return [str(t).strip()[:40] for t in v if str(t).strip()][:15]


__all__ = ["TriageInput", "TriageOutput", "EvidenceItem"]