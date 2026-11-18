"""Small in-process sliding-window rate limiter.

Good enough for a single-container deployment (Hugging Face Spaces, one uvicorn
process). With several replicas each keeps its own counters, so the effective
limit is ``replicas x limit``; put a shared limiter (Redis, an API gateway) in
front if you scale out horizontally.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import HTTPException, Request, status

from app.core.config import get_settings


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def check(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            self._sweep(now)
            hits = self._hits[key]
            cutoff = now - window_seconds
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, int(hits[0] + window_seconds - now) + 1)
                return False, retry_after
            hits.append(now)
            return True, 0

    def _sweep(self, now: float) -> None:
        # Drop idle keys now and then so memory can't grow without bound.
        if now - self._last_sweep < 60:
            return
        self._last_sweep = now
        stale = [k for k, v in self._hits.items() if not v or v[-1] < now - 3700]
        for k in stale:
            del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    """Best-effort client address, honouring X-Forwarded-For only when trusted."""
    if get_settings().TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def rate_limit(
    bucket: str,
    *,
    per_minute: "int | Callable[[], int] | None" = None,
    per_hour: "int | Callable[[], int] | None" = None,
):
    """FastAPI dependency factory enforcing a per-client sliding window.

    ``per_minute``/``per_hour`` default to the global settings. The key is the
    client IP plus ``bucket``, so one noisy route does not starve the others.
    """

    def _dependency(request: Request) -> None:
        settings = get_settings()
        if not settings.RATE_LIMIT_ENABLED:
            return
        per_min = per_minute() if callable(per_minute) else per_minute
        per_hr = per_hour() if callable(per_hour) else per_hour
        minute = per_min if per_min is not None else settings.RATE_LIMIT_PER_MINUTE
        who = client_ip(request)
        ok, retry = limiter.check(f"{bucket}:{who}:m", minute, 60)
        if ok and per_hr is not None:
            ok, retry = limiter.check(f"{bucket}:{who}:h", per_hr, 3600)
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "rate_limited",
                    "message": "Too many requests. Slow down and retry shortly.",
                    "retry_after_seconds": retry,
                },
                headers={"Retry-After": str(retry)},
            )

    return _dependency
