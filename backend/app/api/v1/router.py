from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    meta,
    orchestrator,
    organizations,
    stats,
    threats as threats_endpoints,
)

api_router = APIRouter()

# Meta endpoints (health, identity)
api_router.include_router(meta.router)

# Threats
api_router.include_router(threats_endpoints.router)

# Dashboard stats
api_router.include_router(stats.router)

# Organizations
api_router.include_router(
    organizations.router,
    prefix="/organizations",
    tags=["organizations"],
)

# Agents (individual)
api_router.include_router(
    agents.router,
    prefix="/agents",
    tags=["agents"],
)

# Orchestrator (chained pipeline)
api_router.include_router(
    orchestrator.router,
    prefix="/orchestrator",
    tags=["orchestrator"],
)