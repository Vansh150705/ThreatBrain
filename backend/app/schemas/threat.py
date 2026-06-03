from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# Threat list item — compact shape for the table view
class ThreatListItem(BaseModel):
    id: UUID
    short_id: str
    title: str
    severity: str
    status: str
    confidence: int
    risk_score: int | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    target_ips: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    assigned_to: UUID | None = None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime


# Paginated list response
class ThreatListResponse(BaseModel):
    items: list[ThreatListItem]
    total: int
    page: int
    page_size: int
    has_more: bool


# Full threat detail — includes everything
class ThreatDetail(ThreatListItem):
    description: str | None = None
    attack_chain: list[str] = Field(default_factory=list)
    iocs: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    ai_analysis: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    primary_asset_id: UUID | None = None
    incident_id: UUID | None = None
    resolved_at: datetime | None = None