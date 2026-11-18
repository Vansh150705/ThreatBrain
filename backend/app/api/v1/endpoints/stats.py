from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import CurrentUser, require_viewer
from app.services import soc_metrics, stats_service

router = APIRouter(prefix="/stats", tags=["stats"])


class DashboardStats(BaseModel):
    open_incidents: int
    total_threats: int
    open_threats: int
    critical_threats: int


@router.get("/dashboard", response_model=DashboardStats)
def dashboard_stats(
    user: Annotated[CurrentUser, Depends(require_viewer)],
) -> DashboardStats:
    """Return the aggregate counts shown on the main dashboard."""
    result = stats_service.get_dashboard_stats(user.organization_id)
    return DashboardStats(**result)


@router.get("/soc", summary="SOC performance metrics (MTTD/MTTA/MTTC/MTTR, trends, top lists, agent health)")
def soc_metrics_endpoint(
    user: Annotated[CurrentUser, Depends(require_viewer)],
    days: Annotated[int, Query(ge=1, le=90)] = 7,
) -> dict:
    return soc_metrics.compute(user.organization_id, days)
