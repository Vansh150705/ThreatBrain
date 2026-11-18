from __future__ import annotations

from typing import Any

from tb_common.session import ApiError, ApiSession


class EmitterError(Exception):
    """An event could not be delivered. ``transient`` errors are worth retrying later."""

    def __init__(self, message: str, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class Emitter:
    """Posts normalized events to the backend's ``/ingest/event``.

    Authenticates with a scoped API key (preferred) or email/password. With
    ``async_ingest`` the backend answers 202 immediately and runs the agent
    pipeline in the background, so a slow LLM never stalls log tailing.

    ``http`` is any object exposing ``.post(url, json=, headers=, timeout=)``;
    defaults to ``requests.Session`` and is injected in tests.
    """

    def __init__(
        self,
        base_url: str,
        email: str | None = None,
        password: str | None = None,
        http: Any = None,
        *,
        api_key: str | None = None,
        async_ingest: bool = False,
        session: ApiSession | None = None,
    ) -> None:
        self.session = session or ApiSession(base_url, email, password, api_key=api_key, http=http)
        self.async_ingest = async_ingest

    def post_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        path = "/ingest/event" + ("?async=true" if self.async_ingest else "")
        try:
            return self.session.json("post", path, ok=(200, 202), json=payload, timeout=180)
        except ApiError as exc:
            # 4xx (bad payload, wrong scope) will not improve with time; 5xx/network might.
            transient = exc.__class__.__name__ == "TransientError"
            raise EmitterError(f"ingest failed: {exc}", transient=transient) from exc
