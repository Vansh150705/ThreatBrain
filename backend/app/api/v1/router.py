from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    audit,
    auth,
    incidents,
    meta,
    orchestrator,
    organizations,
    stats,
    threats as threats_endpoints,
)

api_router = APIRouter()

# Meta endpoints (health, identity)
api_router.include_router(meta.router)

# Authentication (signup, login)
api_router.include_router(auth.router)

# Audit trail (read-only)
api_router.include_router(audit.router)

# Threats
api_router.include_router(threats_endpoints.router)

# Incidents
api_router.include_router(incidents.router)

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