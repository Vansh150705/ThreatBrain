from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

log = logging.getLogger("threatbrain.session")

RETRY_STATUSES = {429, 500, 502, 503, 504}


class ApiError(Exception):
    """The backend refused the request (4xx other than auth/rate limit)."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthError(ApiError):
    """Credentials were rejected. Retrying will not help."""


class TransientError(ApiError):
    """Network trouble, 429 or 5xx persisted after all retries. Worth retrying later."""


def _detail(resp: Any) -> str:
    try:
        body = resp.json()
    except Exception:
        return ""
    if isinstance(body, dict):
        d = body.get("detail", body)
        if isinstance(d, dict):
            return str(d.get("message") or d.get("error") or d)[:200]
        return str(d)[:200]
    return str(body)[:200]


class ApiSession:
    """Authenticated, retrying HTTP session against the ThreatBrain API.

    Auth is either a scoped API key (``X-API-Key``, recommended for machines) or
    an email/password login that yields a short-lived bearer token, refreshed
    automatically on 401.
    """

    def __init__(
        self,
        base_url: str,
        email: str | None = None,
        password: str | None = None,
        *,
        api_key: str | None = None,
        http: Any = None,
        max_attempts: int = 3,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key and not (email and password):
            raise ValueError("provide an api_key, or both email and password")
        self.base_url = base_url.rstrip("/")
        self.email, self.password, self.api_key = email, password, api_key
        if http is None:
            import requests

            http = requests.Session()
        self.http = http
        self.max_attempts = max(1, max_attempts)
        self.backoff = backoff
        self._sleep = sleep
        self._token: str | None = None

    # ------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        else:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _login(self) -> None:
        resp = self._send("post", "/auth/login", json={"email": self.email, "password": self.password}, auth=False)
        if resp.status_code != 200:
            raise AuthError(f"login failed ({resp.status_code})", resp.status_code)
        self._token = resp.json()["access_token"]

    def _send(self, method: str, path: str, *, auth: bool = True, **kwargs: Any) -> Any:
        """One logical request with bounded retries on network errors / 429 / 5xx."""
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        last: str = "no attempt made"
        for attempt in range(1, self.max_attempts + 1):
            headers = self._headers() if auth else {"Content-Type": "application/json"}
            try:
                resp = getattr(self.http, method)(url, headers=headers, **kwargs)
            except Exception as exc:  # requests.RequestException, OSError, timeouts
                last = f"{type(exc).__name__}"
                log.warning("request %s %s failed (%s), attempt %d/%d", method.upper(), path, last, attempt, self.max_attempts)
            else:
                if resp.status_code not in RETRY_STATUSES:
                    return resp
                last = f"HTTP {resp.status_code}"
                log.warning("request %s %s -> %s, attempt %d/%d", method.upper(), path, last, attempt, self.max_attempts)
            if attempt < self.max_attempts:
                self._sleep(self.backoff * (2 ** (attempt - 1)))
        raise TransientError(f"{method.upper()} {path} failed after {self.max_attempts} attempts ({last})")

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Authenticated request; returns the response for any non-error status."""
        if not self.api_key and self._token is None:
            self._login()
        resp = self._send(method, path, **kwargs)
        if resp.status_code == 401:
            if self.api_key:
                raise AuthError("API key rejected (revoked, expired or wrong scope)", 401)
            self._login()
            resp = self._send(method, path, **kwargs)
            if resp.status_code == 401:
                raise AuthError("credentials rejected", 401)
        if resp.status_code == 403:
            raise AuthError(f"forbidden: {_detail(resp)}", 403)
        return resp

    def json(self, method: str, path: str, ok: tuple[int, ...] = (200,), **kwargs: Any) -> dict[str, Any]:
        resp = self.request(method, path, **kwargs)
        if resp.status_code not in ok:
            raise ApiError(f"{method.upper()} {path} -> {resp.status_code} {_detail(resp)}", resp.status_code)
        return resp.json()
