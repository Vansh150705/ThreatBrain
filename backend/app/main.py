from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, ORJSONResponse

from app.core.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:

    settings = get_settings()

    # Startup
    print("\n" + "=" * 60)
    print(f"🧠  {settings.APP_NAME}  v{settings.APP_VERSION}")
    print(f"    Environment: {settings.APP_ENV}")
    print(f"    Debug:       {settings.APP_DEBUG}")
    print(f"    Listening:   http://{settings.BACKEND_HOST}:{settings.BACKEND_PORT}")
    print(f"    Docs:        http://localhost:{settings.BACKEND_PORT}/docs")
    print(f"    Supabase:    {settings.SUPABASE_URL}")
    print("=" * 60 + "\n")

    yield  # ← application runs here

    # Shutdown
    print("\n👋  ThreatBrain shutting down. Goodbye.\n")


def create_app() -> FastAPI:

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

    # Request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        """Add an ``X-Process-Time-Ms`` header to every response."""
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.2f}"
        return response

    # Exception handler
    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all so unhandled exceptions return clean JSON
        instead of HTML stack traces."""
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

    return app


app = create_app()