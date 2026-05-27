from __future__ import annotations

from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Mirrors public.severity_level."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StatusLevel(str, Enum):
    """Mirrors public.status_level."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"



class PaginationParams(BaseModel):


    page: int = Field(default=1, ge=1, le=10_000, description="1-indexed page number.")
    page_size: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Items per page (max 100).",
    )

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


class Pagination(BaseModel):
    """Pagination metadata returned alongside list responses."""

    page: int = Field(..., ge=1)
    page_size: int = Field(..., ge=1)
    total: int = Field(..., ge=0, description="Total matching rows.")
    total_pages: int = Field(..., ge=0)
    has_next: bool
    has_previous: bool

    @classmethod
    def build(cls, *, page: int, page_size: int, total: int) -> "Pagination":
        """Construct from raw counts."""
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        return cls(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
            has_next=page < total_pages,
            has_previous=page > 1,
        )


T = TypeVar("T")


class ListResponse(BaseModel, Generic[T]):


    items: list[T]
    pagination: Pagination


class ErrorDetail(BaseModel):
    """Structured error body returned by FastAPI on failures."""

    error: str = Field(..., description="Machine-readable error code.")
    message: str = Field(..., description="Human-readable explanation.")
    field: str | None = Field(
        default=None,
        description="Field name when the error relates to a specific input.",
    )


class ErrorResponse(BaseModel):
    """Top-level envelope returned by FastAPI's exception handlers."""

    detail: ErrorDetail | list[ErrorDetail]

    @field_validator("detail", mode="before")
    @classmethod
    def _coerce_str_to_detail(cls, v):
        # Pydantic raw-string errors get coerced into a single ErrorDetail
        if isinstance(v, str):
            return {"error": "error", "message": v}
        return v