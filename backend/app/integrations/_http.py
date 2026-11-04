"""Shared HTTP plumbing for threat-intel feeds."""

from __future__ import annotations

from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

# Overridable in tests with httpx.MockTransport.
_transport: httpx.BaseTransport | None = None
MAX_BYTES = 2_000_000          # a feed answer is a few KB; anything larger is a fault or an attack, and is not read into memory


class FeedError(Exception):
    """Base class for a feed failing (network, auth, quota...)."""


class FeedNotConfigured(FeedError):
    """The feed has no API key configured."""


class FeedRateLimited(FeedError):
    """The feed's quota is exhausted."""


def get_json(
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, str] | None = None,
    feed: str,
) -> dict[str, Any]:
    @retry(
        retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        reraise=True,
    )
    def _call() -> httpx.Response:
        with httpx.Client(timeout=10.0, transport=_transport) as client, client.stream("GET", url, headers=headers, params=params) as r:
            size = int(r.headers.get("content-length") or 0)
            if size > MAX_BYTES:
                raise FeedError(f"{feed} response too large ({size} bytes)")
            chunks, total = [], 0
            for chunk in r.iter_bytes():
                total += len(chunk)
                if total > MAX_BYTES:
                    raise FeedError(f"{feed} response too large")
                chunks.append(chunk)
            return httpx.Response(r.status_code, content=b"".join(chunks), headers=r.headers, request=r.request)

    try:
        resp = _call()
    except FeedError:
        raise
    except Exception as exc:
        raise FeedError(f"{feed} request failed: {type(exc).__name__}") from exc

    if resp.status_code == 429:
        raise FeedRateLimited(f"{feed} quota exceeded")
    if resp.status_code in (401, 403):
        raise FeedError(f"{feed} authentication failed ({resp.status_code})")
    if resp.status_code == 404:
        return {}
    if resp.status_code != 200:
        raise FeedError(f"{feed} returned {resp.status_code}")
    try:
        body = resp.json()
    except ValueError as exc:
        raise FeedError(f"{feed} returned invalid JSON") from exc
    return body if isinstance(body, dict) else {}
