"""HMAC request signing + replay protection for machine ingestion.

An API key can be created with ``require_signature``. Its signing secret is derived on the server from
``APP_SECRET`` and the key id (never stored) and shown once to the key owner. A signed request carries

    X-TB-Timestamp: <unix seconds>
    X-TB-Signature: v1=<hex HMAC-SHA256(secret, "<ts>.<METHOD>.<path?query>.<sha256(body)>")>

so a captured request cannot be modified (body, path and method are bound), cannot be used later
(timestamp window) and cannot be sent twice (the signature is recorded in ``replay_guard`` until the
window has passed). The API key alone is not enough to ingest once a key requires signing.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from app.core.config import get_settings

WINDOW_SECONDS = 300
REPLAY_TTL_SECONDS = WINDOW_SECONDS * 2 + 60


class SignatureError(Exception):
    def __init__(self, code: str, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def signing_secret(key_id: str) -> str:
    app_secret = get_settings().APP_SECRET
    if len(app_secret) < 32:
        raise SignatureError("signing_unavailable", "APP_SECRET is not configured; signed ingestion is unavailable.", 503)
    return hmac.new(app_secret.encode(), f"tb-ingest-signing:{key_id}".encode(), hashlib.sha256).hexdigest()


def canonical(timestamp: str, method: str, path_qs: str, body: bytes) -> str:
    return f"{timestamp}.{method.upper()}.{path_qs}.{hashlib.sha256(body).hexdigest()}"


def sign(secret: str, timestamp: str, method: str, path_qs: str, body: bytes) -> str:
    return "v1=" + hmac.new(secret.encode(), canonical(timestamp, method, path_qs, body).encode(), hashlib.sha256).hexdigest()


def verify(key_id: str, timestamp: str | None, signature: str | None, method: str, path_qs: str, body: bytes,
           *, now: float | None = None) -> str:
    """Return the accepted signature (for the replay guard) or raise SignatureError."""
    if not timestamp or not signature:
        raise SignatureError("signature_required", "This API key requires X-TB-Timestamp and X-TB-Signature.")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise SignatureError("bad_timestamp", "X-TB-Timestamp must be unix seconds.") from exc
    if abs((now if now is not None else time.time()) - ts) > WINDOW_SECONDS:
        raise SignatureError("stale_timestamp", "Request timestamp is outside the accepted window.")
    expected = sign(signing_secret(key_id), timestamp, method, path_qs, body)
    if not hmac.compare_digest(expected, signature.strip().lower()):
        raise SignatureError("bad_signature", "Request signature does not match.")
    return expected
