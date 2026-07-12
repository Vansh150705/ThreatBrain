from __future__ import annotations

from typing import Any


class EmitterError(Exception):
    pass


class Emitter:
    """Authenticates against the backend and posts events to /ingest/event.

    ``http`` is any object exposing ``.post(url, json=, headers=, timeout=)``
    returning a response with ``.status_code`` and ``.json()``. Defaults to a
    real ``requests.Session``; injected in tests.
    """

    def __init__(self, base_url: str, email: str, password: str, http: Any = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        if http is None:
            import requests

            http = requests.Session()
        self.http = http
        self._token: str | None = None

    def _login(self) -> None:
        resp = self.http.post(
            f"{self.base_url}/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise EmitterError(f"login failed: {resp.status_code}")
        self._token = resp.json()["access_token"]

    def post_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._token is None:
            self._login()

        resp = self._post_event(payload)
        if resp.status_code == 401:
            # token expired mid-run; re-login once and retry
            self._login()
            resp = self._post_event(payload)

        if resp.status_code != 200:
            raise EmitterError(f"ingest failed: {resp.status_code} {resp.json()}")
        return resp.json()

    def _post_event(self, payload: dict[str, Any]):
        return self.http.post(
            f"{self.base_url}/ingest/event",
            json=payload,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            timeout=180,
        )
