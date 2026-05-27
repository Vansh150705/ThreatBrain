from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class OrgPlan(str, Enum):
    """Mirrors public.plan_tier."""

    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class OrgStatus(str, Enum):
    """Mirrors public.org_status."""

    TRIAL = "trial"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validate_slug(slug: str) -> str:
    """Same rule as organizations_slug_format CHECK constraint."""
    if not _SLUG_RE.match(slug):
        raise ValueError(
            "Slug must be lowercase letters, digits, and single hyphens "
            "(e.g., 'acme-corp')."
        )
    return slug

class OrganizationBase(BaseModel):
    """Fields shared by create/update/response."""

    name: str = Field(
        ...,
        min_length=2,
        max_length=120,
        description="Human-readable organization name.",
        examples=["Acme Corporation"],
    )
    slug: str = Field(
        ...,
        min_length=2,
        max_length=60,
        description="URL-safe unique identifier.",
        examples=["acme-corp"],
    )
    plan: OrgPlan = Field(default=OrgPlan.FREE)
    status: OrgStatus = Field(default=OrgStatus.TRIAL)
    billing_email: EmailStr | None = Field(
        default=None, description="Optional billing/contact email."
    )
    settings: dict[str, Any] = Field(
        default_factory=dict, description="Free-form configuration."
    )

    @field_validator("slug")
    @classmethod
    def validate_slug_format(cls, v: str) -> str:
        return _validate_slug(v)


class OrganizationCreate(BaseModel):
    """Request body for creating a new organization."""

    name: str = Field(..., min_length=2, max_length=120)
    slug: str = Field(..., min_length=2, max_length=60)
    plan: OrgPlan = Field(default=OrgPlan.FREE)
    billing_email: EmailStr | None = None
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug_format(cls, v: str) -> str:
        return _validate_slug(v)


class OrganizationUpdate(BaseModel):


    name: str | None = Field(default=None, min_length=2, max_length=120)
    plan: OrgPlan | None = None
    status: OrgStatus | None = None
    billing_email: EmailStr | None = None
    settings: dict[str, Any] | None = None
    # NOTE: slug intentionally NOT mutable — changing it breaks URLs / FKs.


class OrganizationResponse(OrganizationBase):
    """Full organization payload returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None