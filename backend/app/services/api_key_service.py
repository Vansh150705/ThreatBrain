"""Machine credentials (API keys) for collectors, executors and webhooks.

Keys are shown exactly once at creation. Only a SHA-256 digest is stored: the
secret part is 256 random bits, so a fast hash is appropriate (there is nothing
to brute-force) and lookups can be an indexed equality match.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

KEY_PREFIX = "tbk_"
VALID_SCOPES = {"ingest", "executor"}
# Roles an API key may carry. Keys never get admin/owner powers.
VALID_KEY_ROLES = {"analyst"}
_COLUMNS = "id, name, key_prefix, scopes, role, created_at, last_used_at, expires_at, revoked_at, created_by"


def generate_key() -> str:
    return f"{KEY_PREFIX}{secrets.token_urlsafe(32)}"


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def looks_like_key(raw: str) -> bool:
    return raw.startswith(KEY_PREFIX) and len(raw) >= 24


def create_api_key(
    *,
    organization_id: str,
    name: str,
    scopes: list[str],
    created_by: str | None,
    expires_at: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Create a key. Returns (row, raw_key); the raw key is not recoverable later."""
    bad = [s for s in scopes if s not in VALID_SCOPES]
    if bad or not scopes:
        raise ValueError(f"scopes must be a non-empty subset of {sorted(VALID_SCOPES)}")
    raw = generate_key()
    row = (
        get_supabase_admin()
        .table("api_keys")
        .insert(
            {
                "organization_id": organization_id,
                "name": name,
                "key_prefix": raw[:12],
                "key_hash": hash_key(raw),
                "scopes": sorted(set(scopes)),
                "role": "analyst",
                "created_by": created_by,
                "expires_at": expires_at,
            }
        )
        .execute()
        .data[0]
    )
    return {k: row.get(k) for k in _COLUMNS.split(", ")}, raw


def list_api_keys(organization_id: str) -> list[dict[str, Any]]:
    return (
        get_supabase_admin()
        .table("api_keys")
        .select(_COLUMNS)
        .eq("organization_id", organization_id)
        .order("created_at", desc=True)
        .execute()
        .data
        or []
    )


def revoke_api_key(organization_id: str, key_id: str) -> dict[str, Any] | None:
    rows = (
        get_supabase_admin()
        .table("api_keys")
        .update({"revoked_at": datetime.now(timezone.utc).isoformat()})
        .eq("organization_id", organization_id)
        .eq("id", key_id)
        .is_("revoked_at", "null")
        .execute()
        .data
        or []
    )
    return rows[0] if rows else None


def authenticate_api_key(raw: str) -> dict[str, Any] | None:
    """Return the key row for a valid, unexpired, unrevoked key; else None."""
    if not looks_like_key(raw):
        return None
    admin = get_supabase_admin()
    rows = (
        admin.table("api_keys")
        .select("id, organization_id, name, scopes, role, expires_at, revoked_at, last_used_at")
        .eq("key_hash", hash_key(raw))
        .limit(1)
        .execute()
        .data
        or []
    )
    if not rows:
        return None
    row = rows[0]
    if row.get("revoked_at"):
        return None
    expires = row.get("expires_at")
    if expires:
        try:
            exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return None
        except ValueError:
            return None
    _touch_last_used(row)
    return row


def _touch_last_used(row: dict[str, Any]) -> None:
    """Stamp last_used_at, at most once a minute per key (best effort)."""
    now = datetime.now(timezone.utc)
    last = row.get("last_used_at")
    if last:
        try:
            prev = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=timezone.utc)
            if (now - prev).total_seconds() < 60:
                return
        except ValueError:
            pass
    try:
        get_supabase_admin().table("api_keys").update(
            {"last_used_at": now.isoformat()}
        ).eq("id", row["id"]).execute()
    except Exception:
        log.warning("api_key_touch_failed", key_id=row.get("id"))
