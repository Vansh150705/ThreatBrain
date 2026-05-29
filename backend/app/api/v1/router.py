from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import agents, meta, organizations

api_router = APIRouter()

# Meta endpoints (health, identity, RBAC tests)
api_router.include_router(meta.router)

# Organizations
api_router.include_router(
    organizations.router,
    prefix="/organizations",
    tags=["organizations"],
)

# Agents
api_router.include_router(
    agents.router,
    prefix="/agents",
    tags=["agents"],
)