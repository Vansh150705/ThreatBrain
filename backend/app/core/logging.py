from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    merge_contextvars,
    unbind_contextvars,
)

from app.core.config import get_settings


def setup_logging() -> None:
    """Configure structlog + stdlib logging. Call once at startup."""
    settings = get_settings()
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    # shared processors run on every log call
    shared_processors: list[structlog.types.Processor] = [
        # Pull request_id / user_id (etc.) from contextvars
        merge_contextvars,
        # Add timestamp in ISO 8601
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        # Add log level as a field
        structlog.stdlib.add_log_level,
        # Add logger name as a field
        structlog.stdlib.add_logger_name,
        # Render stack/exception info if present
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        # Resolve any callable args (lazy evaluation)
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                structlog.processors.CallsiteParameter.MODULE,
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
            ]
        ),
    ]

    # Choose output renderer based on format 
    if settings.LOG_FORMAT == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.plain_traceback,
        )

    # Configure structlog
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        cache_logger_on_first_use=True,
    )

    # wire stdlib logging through structlog formatter
    # This captures logs from FastAPI, uvicorn, supabase-py, httpx, etc.
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Clear any handlers attached by uvicorn / other libs
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # Quiet down chatty libraries
    for noisy in ("httpx", "httpcore", "hpack", "asyncio", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound to ``name``.

    Convention: use the module's ``__name__`` as the logger name.

        log = get_logger(__name__)
        log.info("user_signed_up", user_id=user.id)
    """
    return structlog.get_logger(name)


def bind_request_context(**kwargs: Any) -> None:
    """Bind values to the current async-task's log context.

    Anything bound here will appear on every log line emitted
    during the rest of the request (until ``clear_request_context``).
    """
    bind_contextvars(**kwargs)


def unbind_request_keys(*keys: str) -> None:
    """Remove specific keys from the current log context."""
    unbind_contextvars(*keys)


def clear_request_context() -> None:
    """Wipe all per-request log context."""
    clear_contextvars()