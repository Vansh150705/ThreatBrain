from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import CurrentUser, get_current_user
from app.services import stats_service

router = APIRouter(prefix="/stats", tags=["stats"])


class DashboardStats(BaseModel):
    open_incidents: int
    total_threats: int
    open_threats: int
    critical_threats: int


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard_stats(
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> DashboardStats:
    """Return the aggregate counts shown on the main dashboard."""
    result = stats_service.get_dashboard_stats(user.organization_id)
    return DashboardStats(**result)