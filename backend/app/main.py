from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse

from app.api.deps import CurrentUser, get_current_user, require_admin
from app.core.config import get_settings
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    get_logger,
    setup_logging,
)
from app.services.supabase_client import supabase_health_check

# Initialize logging immediately so import-time logs are captured too.
setup_logging()
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Run startup/shutdown logic."""
    settings = get_settings()

    log.info(
        "app_starting",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        debug=settings.APP_DEBUG,
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        supabase_url=str(settings.SUPABASE_URL),
        docs_url=f"http://localhost:{settings.BACKEND_PORT}/docs",
    )

    yield

    log.info("app_shutting_down")

def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "The Neural SOC — where 7 specialized AI agents autonomously "
            "detect, investigate, and respond to cyber threats in real time."
        ),
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-Id", "X-Process-Time-Ms"],
    )

    # Request context + timing middleware
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        """Attach a request_id to logs and add timing headers."""
        request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:12]
        bind_request_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
        )

        start = time.perf_counter()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            log.info(
                "request_completed",
                duration_ms=round(elapsed_ms, 2),
                status_code=response.status_code if response is not None else 500,
            )
            clear_request_context()
            if response is not None:
                response.headers["X-Request-Id"] = request_id
                response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.2f}"

    # Exception handler
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all so unhandled exceptions return clean JSON."""
        log.exception(
            "unhandled_exception",
            exception_type=type(exc).__name__,
            exception_message=str(exc),
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "internal_server_error",
                "message": (
                    str(exc) if settings.APP_DEBUG else "Something went wrong."
                ),
                "path": str(request.url.path),
            },
        )

    # Routes
    @app.get("/", tags=["meta"])
    async def root() -> dict[str, object]:
        """API info banner."""
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "tagline": "The Neural SOC — Where AI Agents Converge to Defend",
            "docs": "/docs",
            "health": "/health",
        }

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, object]:
        """Liveness probe used by Railway, load balancers, uptime monitors."""
        return {
            "status": "ok",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "timestamp_unix": int(time.time()),
        }

    @app.get("/health/db", tags=["meta"])
    async def health_db() -> dict[str, object]:
        """Deep health check — confirms Supabase connectivity."""
        db_status = supabase_health_check()
        return {
            "status": "ok" if db_status["ok"] else "degraded",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "database": db_status,
            "timestamp_unix": int(time.time()),
        }

    # ── Auth test endpoints (delete once real routes exist) ─
    @app.get("/api/v1/me", tags=["meta"])
    async def whoami(
        user: CurrentUser = Depends(get_current_user),
    ) -> dict[str, object]:
        """Returns the authenticated user's resolved identity."""
        return {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "status": user.status,
            "organization_id": user.organization_id,
            "avatar_url": user.avatar_url,
        }

    @app.get("/api/v1/admin-only", tags=["meta"])
    async def admin_only(
        user: CurrentUser = Depends(require_admin),
    ) -> dict[str, object]:
        """Test endpoint that only admins/owners can reach."""
        return {
            "message": f"Hello {user.full_name or user.email}, you're an admin.",
            "role": user.role,
        }

    return app


app = create_app()