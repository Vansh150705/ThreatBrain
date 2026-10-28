"""Machine credentials (API keys) for collectors, executors and webhooks.

Keys are shown exactly once at creation. Only a SHA-256 digest is stored: the
secret part is 256 random bits, so a fast hash is appropriate (there is nothing
to brute-force) and lookups can be an indexed equality match.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

KEY_PREFIX = "tbk_"
VALID_SCOPES = {"ingest", "executor"}
# Roles an API key may carry. Keys never get admin/owner powers.
VALID_KEY_ROLES = {"analyst"}
_COLUMNS = ("id, name, key_prefix, scopes, role, created_at, last_used_at, expires_at, revoked_at, created_by, "
            "require_signature, last_used_ip, use_count, rotated_from")


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
    require_signature: bool = False,
    rotated_from: str | None = None,
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
                "require_signature": require_signature,
                "rotated_from": rotated_from,
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
        .update({"revoked_at": datetime.now(UTC).isoformat()})
        .eq("organization_id", organization_id)
        .eq("id", key_id)
        .is_("revoked_at", "null")
        .execute()
        .data
        or []
    )
    return rows[0] if rows else None


def rotate_api_key(organization_id: str, key_id: str, *, grace_hours: int, created_by: str | None) -> tuple[dict[str, Any], str, dict[str, Any]] | None:
    """Issue a replacement with the same name/scopes/signing policy; the old key keeps working until the grace period ends."""
    client = get_supabase_admin()
    rows = (client.table("api_keys").select("*").eq("organization_id", organization_id).eq("id", key_id)
            .is_("revoked_at", "null").limit(1).execute().data)
    if not rows:
        return None
    old = rows[0]
    row, raw = create_api_key(
        organization_id=organization_id, name=f"{old['name']} (rotated {datetime.now(UTC):%Y-%m-%d})"[:100],
        scopes=list(old["scopes"]), created_by=created_by,
        expires_at=old.get("expires_at"), require_signature=bool(old.get("require_signature")), rotated_from=key_id,
    )
    cutoff = datetime.now(UTC) + timedelta(hours=grace_hours)
    old_exp = old.get("expires_at")
    if old_exp:
        try:
            existing = datetime.fromisoformat(str(old_exp).replace("Z", "+00:00"))
            cutoff = min(cutoff, existing if existing.tzinfo else existing.replace(tzinfo=UTC))
        except ValueError:
            pass
    client.table("api_keys").update({"expires_at": cutoff.isoformat()}).eq("id", key_id).execute()
    return row, raw, {"id": key_id, "expires_at": cutoff.isoformat()}


def authenticate_api_key(raw: str, *, client_ip: str | None = None) -> dict[str, Any] | None:
    """Return the key row for a valid, unexpired, unrevoked key; else None."""
    if not looks_like_key(raw):
        return None
    admin = get_supabase_admin()
    rows = (
        admin.table("api_keys")
        .select("id, organization_id, name, scopes, role, expires_at, revoked_at, last_used_at, require_signature, use_count, last_used_ip")
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
                exp = exp.replace(tzinfo=UTC)
            if exp <= datetime.now(UTC):
                return None
        except ValueError:
            return None
    _touch_last_used(row, client_ip)
    return row


def _touch_last_used(row: dict[str, Any], client_ip: str | None = None) -> None:
    """Record last use (time, source address) and a use counter, at most once a minute per key.

    ``use_count`` is therefore approximate (it counts distinct minutes of activity, not requests);
    exact request counts belong in metrics, not in a row update on the auth hot path.
    """
    now = datetime.now(UTC)
    last = row.get("last_used_at")
    if last:
        try:
            prev = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            if prev.tzinfo is None:
                prev = prev.replace(tzinfo=UTC)
            if (now - prev).total_seconds() < 60 and (not client_ip or client_ip == row.get("last_used_ip")):
                return
        except ValueError:
            pass
    try:
        get_supabase_admin().table("api_keys").update(
            {"last_used_at": now.isoformat(), "last_used_ip": client_ip, "use_count": int(row.get("use_count") or 0) + 1}
        ).eq("id", row["id"]).execute()
    except Exception:
        log.warning("api_key_touch_failed", key_id=row.get("id"))


class ReplayedRequest(Exception):
    pass


def record_signature(key_id: str, signature: str) -> None:
    """Remember an accepted signature until its timestamp window has passed. A repeat is a replay.

    Fails closed: if the guard cannot be written, the request is refused (503) rather than accepted
    without replay protection.
    """
    from app.core import signing

    expires = datetime.now(UTC) + timedelta(seconds=signing.REPLAY_TTL_SECONDS)
    try:
        rows = (
            get_supabase_admin().table("replay_guard")
            .upsert({"key_id": key_id, "signature": signature, "expires_at": expires.isoformat()},
                    on_conflict="key_id,signature", ignore_duplicates=True)
            .execute().data
        )
    except Exception as exc:
        log.exception("replay_guard_unavailable")
        raise signing.SignatureError("replay_guard_unavailable", "Replay protection is unavailable; try again.", 503) from exc
    if not rows:
        raise signing.SignatureError("replayed_request", "This signed request was already processed.", 409)
