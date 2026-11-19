"""Request-body size cap that also holds for chunked uploads.

Checking ``Content-Length`` alone is not enough: a client using ``Transfer-Encoding: chunked`` sends no
length, so the whole body would be buffered before any size check ran. This ASGI middleware counts the
bytes as they arrive and stops reading as soon as the cap is crossed.
"""

from __future__ import annotations

from collections.abc import Iterable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class _BodyTooLarge(Exception):
    pass


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int, path_prefixes: Iterable[str]) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.path_prefixes = tuple(path_prefixes)

    def _too_large(self) -> JSONResponse:
        mb = self.max_bytes / 1_000_000
        return JSONResponse(
            {"detail": f"Payload too large (max {mb:g} MB)."},
            status_code=413,
            headers={"Connection": "close"},
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith(self.path_prefixes):
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._too_large()(scope, receive, send)
            return

        received = 0
        exceeded = False
        responded = False

        async def reject() -> None:
            nonlocal responded
            if not responded:
                responded = True
                await self._too_large()(scope, receive, send)

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    exceeded = True
                    raise _BodyTooLarge
            return message

        async def guarded_send(message: Message) -> None:
            # FastAPI turns any error raised while reading a JSON body into a generic 400. Once the cap has
            # been crossed, the client must see 413 instead, whatever the app tries to answer.
            if exceeded:
                await reject()
                return
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except Exception:
            if not exceeded:
                raise
        if exceeded:
            await reject()
