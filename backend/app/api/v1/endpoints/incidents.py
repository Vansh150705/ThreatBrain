from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import CurrentUser, get_current_user
from app.schemas.incident import (
    IncidentDetail,
    IncidentListItem,
    IncidentListResponse,
)
from app.services import incident_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


# List incidents
@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    severity: Annotated[str | None, Query()] = None,
    incident_status: Annotated[str | None, Query(alias="status")] = None,
    priority: Annotated[str | None, Query()] = None,
    sort_by: Annotated[str, Query()] = "created_at",
    sort_dir: Annotated[str, Query()] = "desc",
) -> IncidentListResponse:
    """List incidents for the caller's organization with filters, sorting, and pagination."""
    result = incident_service.list_incidents(
        organization_id=user.organization_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=incident_status,
        priority=priority,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return IncidentListResponse(
        items=[IncidentListItem(**row) for row in result["items"]],
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
        has_more=result["has_more"],
    )


# Detail by UUID or short_id
@router.get("/{identifier}", response_model=IncidentDetail)
async def get_incident(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> IncidentDetail:
    """Fetch a single incident by UUID or short_id."""
    incident = None
    try:
        uuid_value = UUID(identifier)
        incident = incident_service.get_incident_detail(user.organization_id, uuid_value)
    except ValueError:
        incident = incident_service.get_incident_by_short_id(user.organization_id, identifier)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found",
        )

    return IncidentDetail(**incident)


# Threats grouped under an incident
@router.get("/{identifier}/threats")
async def get_incident_threats(
    identifier: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    """Fetch the threats that belong to an incident."""
    incident = None
    try:
        uuid_value = UUID(identifier)
        incident = incident_service.get_incident_detail(user.organization_id, uuid_value)
    except ValueError:
        incident = incident_service.get_incident_by_short_id(user.organization_id, identifier)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{identifier}' not found",
        )

    threats = incident_service.list_threats_for_incident(
        user.organization_id,
        UUID(incident["id"]),
    )
    return {"items": threats, "total": len(threats)}