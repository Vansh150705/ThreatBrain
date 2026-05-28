from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import meta

# The top-level v1 router. main.py mounts this under /api/v1.
api_router = APIRouter()

# Resource routers
# Meta endpoints (health, me, etc.) — no extra prefix.
api_router.include_router(meta.router)
