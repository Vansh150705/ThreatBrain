from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    get_logger,
    setup_logging,
)

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

    # Root endpoint 
    @app.get("/", tags=["meta"])
    async def root() -> dict[str, object]:
        """API info banner."""
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "tagline": "The Neural SOC — Where AI Agents Converge to Defend",
            "docs": "/docs",
            "api": "/api/v1",
        }

    #  Mount the versioned API router 
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()