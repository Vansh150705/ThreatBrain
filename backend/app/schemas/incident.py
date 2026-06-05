from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# Incident list item — compact for the table view
class IncidentListItem(BaseModel):
    id: UUID
    short_id: str
    title: str
    severity: str
    status: str
    priority: str
    confidence: int
    risk_score: int | None = None
    threat_count: int = 0
    asset_count: int = 0
    kill_chain: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    assigned_to: UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


# Paginated response
class IncidentListResponse(BaseModel):
    items: list[IncidentListItem]
    total: int
    page: int
    page_size: int
    has_more: bool


# Full incident detail — adds the heavy jsonb fields
class IncidentDetail(IncidentListItem):
    description: str | None = None
    affected_asset_ids: list[str] = Field(default_factory=list)
    attribution: dict[str, Any] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    playbook_runs: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    ai_summary: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)