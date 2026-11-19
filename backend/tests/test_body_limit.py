"""The ingest body cap must hold for chunked uploads (no Content-Length), not just declared sizes."""

from __future__ import annotations

import asyncio

from app.api.v1.endpoints.ingest import MAX_BODY_BYTES
from app.core.body_limit import BodySizeLimitMiddleware


def _chunks(total: int, size: int = 64_000):
    sent = 0
    while sent < total:
        n = min(size, total - sent)
        sent += n
        yield b"A" * n


def test_chunked_oversized_body_is_rejected_with_413(client, auth):
    # A generator body makes httpx use Transfer-Encoding: chunked, so there is no Content-Length header.
    r = client.post(
        "/api/v1/ingest/webhook/generic",
        content=_chunks(MAX_BODY_BYTES * 3),
        headers={**auth("analyst_a"), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_chunked_oversized_json_endpoint_is_rejected_with_413(client, auth):
    r = client.post(
        "/api/v1/ingest/event",
        content=_chunks(MAX_BODY_BYTES * 3),
        headers={**auth("analyst_a"), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_declared_oversized_body_is_rejected_with_413(client, auth):
    big = b'{"x": "' + b"A" * (MAX_BODY_BYTES + 10) + b'"}'
    r = client.post(
        "/api/v1/ingest/events",
        content=big,
        headers={**auth("analyst_a"), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_chunked_body_within_limit_is_still_accepted(client, auth):
    body = b'{"events": [{"title": "small", "event_type": "e"}]}'
    r = client.post(
        "/api/v1/ingest/events",
        content=iter([body[:10], body[10:]]),
        headers={**auth("analyst_a"), "Content-Type": "application/json"},
    )
    assert r.status_code == 202


def test_other_paths_are_not_limited():
    """The middleware only applies to its configured prefixes."""
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["path"])

    mw = BodySizeLimitMiddleware(app, max_bytes=10, path_prefixes=("/limited",))

    async def run():
        async def receive():
            return {"type": "http.request", "body": b"x" * 100, "more_body": False}

        async def send(message):
            pass

        await mw({"type": "http", "path": "/elsewhere", "headers": []}, receive, send)

    asyncio.run(run())
    assert seen == ["/elsewhere"]
