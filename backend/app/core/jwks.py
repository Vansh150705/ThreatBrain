"""JWKS fetching + caching for asymmetric JWT verification (Supabase signing keys, external OIDC IdP)."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt

from app.core.logging import get_logger

log = get_logger(__name__)

TTL_SECONDS = 600.0
MIN_REFRESH_SECONDS = 30.0    # an unknown `kid` may force a refetch, but not more often than this
MAX_BYTES = 256_000

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}
_last_refresh: dict[str, float] = {}


class JWKSError(Exception):
    pass


def _http_get_json(url: str) -> dict[str, Any]:
    """Fetch a JWKS document. Replaced in tests; bounded in time and size."""
    with httpx.Client(timeout=5.0, follow_redirects=False) as c:
        r = c.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            raise JWKSError("JWKS document too large")
        return r.json()


def _load(url: str) -> dict[str, dict[str, Any]]:
    doc = _http_get_json(url)
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        raise JWKSError("not a JWKS document")
    by_kid = {k["kid"]: k for k in keys if isinstance(k, dict) and k.get("kid")}
    if not by_kid:
        raise JWKSError("JWKS has no keys with a kid")
    _cache[url] = (time.monotonic(), by_kid)
    _last_refresh[url] = time.monotonic()
    return by_kid


def reset_cache() -> None:
    with _lock:
        _cache.clear()
        _last_refresh.clear()


def get_signing_key(url: str, kid: str | None, allowed_algs: set[str]) -> Any:
    """Return the verification key for ``kid``. Raises JWKSError if it cannot be established."""
    if not kid:
        raise JWKSError("token has no kid")
    now = time.monotonic()
    with _lock:
        cached = _cache.get(url)
        keys = cached[1] if cached and now - cached[0] < TTL_SECONDS else None
        if keys is None or (kid not in keys and now - _last_refresh.get(url, 0) > MIN_REFRESH_SECONDS):
            try:
                keys = _load(url)
            except Exception as exc:
                if cached:      # serve stale keys during an IdP outage rather than locking everyone out
                    log.warning("jwks_refresh_failed_using_stale", url=url, error=str(exc)[:120])
                    keys = cached[1]
                else:
                    raise JWKSError(f"could not fetch JWKS: {exc}") from exc
    jwk = keys.get(kid)
    if jwk is None:
        raise JWKSError("unknown signing key id")
    if jwk.get("alg") and jwk["alg"] not in allowed_algs:
        raise JWKSError("signing key algorithm not allowed")
    if jwk.get("use") not in (None, "sig"):
        raise JWKSError("key is not a signature key")
    try:
        return jwt.PyJWK(jwk).key
    except Exception as exc:
        raise JWKSError("unusable signing key") from exc
