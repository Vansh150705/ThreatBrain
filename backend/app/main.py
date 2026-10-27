from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse
from pydantic import ValidationError

from app.agents.base import AgentConfigError
from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import (
    bind_request_context,
    clear_request_context,
    get_logger,
    setup_logging,
)
from app.core.ratelimit import client_ip, limiter
from app.services.llm_service import LLMError

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
        llm_configured=bool(settings.GROQ_API_KEY),
    )

    # A restart kills in-flight background pipelines; don't leave them "running".
    try:
        from app.services import pipeline_service

        pipeline_service.recover_stale_runs()
    except Exception:
        log.exception("pipeline_recovery_failed")

    scheduler = None
    if settings.HUNT_INTERVAL_MINUTES > 0:
        from app.services.scheduler import HuntScheduler

        scheduler = HuntScheduler(interval_minutes=settings.HUNT_INTERVAL_MINUTES)
        scheduler.start()

    yield

    if scheduler is not None:
        scheduler.stop()
    try:
        from app.services import pipeline_service

        pipeline_service.shutdown()
    except Exception:
        log.exception("pipeline_shutdown_failed")
    log.info("app_shutting_down")


_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


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
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-API-Key"],
        expose_headers=["X-Request-Id", "X-Process-Time-Ms"],
    )

    # Request context, global rate limit, security headers and timing
    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        """Attach a request_id to logs, throttle abusive clients, add headers."""
        raw_id = request.headers.get("X-Request-Id", "")
        # Never echo arbitrary client input into logs/headers.
        request_id = raw_id if raw_id.isalnum() and len(raw_id) <= 64 else uuid.uuid4().hex[:12]
        bind_request_context(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=client_ip(request),
        )

        start = time.perf_counter()
        response = None
        try:
            if (
                settings.RATE_LIMIT_ENABLED
                and request.method != "OPTIONS"
                and request.url.path.startswith("/api/")
                and not request.url.path.startswith("/api/v1/health")
            ):
                ok, retry = limiter.check(
                    f"global:{client_ip(request)}", settings.RATE_LIMIT_PER_MINUTE, 60
                )
                if not ok:
                    response = ORJSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={
                            "detail": {
                                "error": "rate_limited",
                                "message": "Too many requests. Slow down and retry shortly.",
                                "retry_after_seconds": retry,
                            }
                        },
                        headers={"Retry-After": str(retry)},
                    )
            if response is None:
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
                for name, value in _SECURITY_HEADERS.items():
                    response.headers.setdefault(name, value)
                if settings.is_production:
                    response.headers.setdefault(
                        "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
                    )

    # Exception handlers
    @app.exception_handler(LLMError)
    async def llm_error_handler(request: Request, exc: LLMError):
        log.warning("llm_unavailable", error=str(exc)[:200], path=request.url.path)
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": {
                "error": "llm_unavailable",
                "message": "The language model is unavailable right now. Try again shortly.",
            }},
        )

    @app.exception_handler(ValidationError)
    async def model_output_validation_handler(request: Request, exc: ValidationError):
        # Request bodies are validated by FastAPI (422). A ValidationError that
        # reaches here was raised while parsing a model's reply, i.e. an upstream fault.
        log.warning("agent_output_invalid", path=request.url.path, errors=exc.error_count())
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={"detail": {
                "error": "agent_output_invalid",
                "message": "The language model returned output that did not match the expected schema.",
            }},
        )

    @app.exception_handler(AgentConfigError)
    async def agent_config_error_handler(request: Request, exc: AgentConfigError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": {"error": "agent_not_available", "message": str(exc)}},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all so unhandled exceptions return clean JSON (no internals)."""
        log.exception(
            "unhandled_exception",
            exception_type=type(exc).__name__,
            exception_message=str(exc),
        )
        body: dict[str, object] = {
            "error": "internal_server_error",
            "message": "Something went wrong.",
            "path": str(request.url.path),
        }
        if settings.APP_DEBUG and not settings.is_production:
            body["message"] = str(exc)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=body)

    # Root endpoint
    @app.get("/", tags=["meta"])
    async def root() -> dict[str, object]:
        """API info banner."""
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.APP_ENV,
            "tagline": "The Neural SOC — Where AI Agents Converge to Defend",
            "docs": "/docs" if not settings.is_production else None,
            "api": "/api/v1",
        }

    #  Mount the versioned API router
    app.include_router(api_router, prefix="/api/v1")

    return app


app = create_app()
