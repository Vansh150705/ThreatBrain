from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import meta, organizations

# The top-level v1 router. main.py mounts this under /api/v1.
api_router = APIRouter()

# Meta (health, identity, RBAC tests) — no extra prefix 
api_router.include_router(meta.router)

# Organizations 
api_router.include_router(
    organizations.router,
    prefix="/organizations",
    tags=["organizations"],
)
