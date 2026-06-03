from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import CurrentUser, get_current_user
from app.schemas.threat import ThreatDetail, ThreatListItem, ThreatListResponse
from app.services import threat_service

router = APIRouter(prefix="/threats", tags=["threats"])


# List threats
@router.get("", response_model=ThreatListResponse)
async def list_threats(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1, description="Page number, starts at 1")] = 1,
    page_size: Annotated[int, Query(ge=1, le=100, description="Items per page (max 100)")] = 25,
    severity: Annotated[str | None, Query(description="Filter by severity: critical, high, medium, low, info")] = None,
    threat_status: Annotated[str | None, Query(alias="status", description="Filter by status: open, investigating, resolved, false_positive")] = None,
    sort_by: Annotated[str, Query(description="Sort field: created_at, severity, status, confidence")] = "created_at",
    sort_dir: Annotated[str, Query(description="Sort direction: asc or desc")] = "desc",
) -> ThreatListResponse:
    """List threats for the caller's organization with filters, sorting, and pagination."""
    result = threat_service.list_threats(
        organization_id=user.organization_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=threat_status,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return ThreatListResponse(
        items=[ThreatListItem(**row) for row in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        has_more=result["has_more"],
    )


# Threat detail by UUID or short_id
@router.get("/{identifier}", response_model=ThreatDetail)
async def get_threat(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ThreatDetail:
    """Fetch a single threat by UUID or short_id."""
    # Try UUID first, fall back to short_id
    threat = None
    try:
        uuid_value = UUID(identifier)
        threat = threat_service.get_threat_detail(user.organization_id, uuid_value)
    except ValueError:
        threat = threat_service.get_threat_by_short_id(user.organization_id, identifier)

    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat '{identifier}' not found",
        )

    return ThreatDetail(**threat)