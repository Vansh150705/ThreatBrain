"""Machine credentials for collectors, executors and webhooks (admin only)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser, require_admin
from app.services import api_key_service, case_service

router = APIRouter(prefix="/api-keys", tags=["api-keys"])

Scope = Literal["ingest", "executor"]


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Scope] = Field(min_length=1, description="ingest: send events. executor: poll/report approved actions.")
    expires_in_days: int | None = Field(default=None, ge=1, le=730)
    require_signature: bool = Field(default=False, description="Require HMAC-signed, replay-protected requests (needs APP_SECRET).")


class ApiKeyItem(BaseModel):
    id: str
    name: str
    key_prefix: str
    scopes: list[str]
    role: str
    created_at: str
    last_used_at: str | None = None
    expires_at: str | None = None
    revoked_at: str | None = None
    require_signature: bool = False
    last_used_ip: str | None = None
    use_count: int = 0
    rotated_from: str | None = None


class ApiKeyCreated(ApiKeyItem):
    api_key: str = Field(description="Shown once. Store it in your secret manager; it cannot be retrieved later.")
    signing_secret: str | None = Field(default=None, description="Shown once, with the key, when require_signature is on. Use it to sign requests (see docs/SECURITY.md).")


class ApiKeyList(BaseModel):
    items: list[ApiKeyItem]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(body: ApiKeyCreate, user: Annotated[CurrentUser, Depends(require_admin)]) -> ApiKeyCreated:
    if user.auth_method != "jwt":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot mint other API keys.")
    _require_signing_available(body.require_signature)
    expires = (
        (datetime.now(UTC) + timedelta(days=body.expires_in_days)).isoformat()
        if body.expires_in_days
        else None
    )
    try:
        row, raw = api_key_service.create_api_key(
            organization_id=user.organization_id,
            name=body.name.strip(),
            scopes=list(body.scopes),
            created_by=user.id,
            expires_at=expires,
            require_signature=body.require_signature,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    secret = _signing_secret_or_none(row, body.require_signature)
    case_service.audit(
        user, action="api_key.created", target_type="api_key",
        row={"id": row["id"], "title": body.name},
        changes={"scopes": body.scopes, "expires_at": expires, "require_signature": body.require_signature},
        severity="high",
    )
    return ApiKeyCreated(**{**row, "created_at": str(row["created_at"])}, api_key=raw, signing_secret=secret)


def _signing_secret_or_none(row: dict, wanted: bool) -> str | None:
    if not wanted:
        return None
    from app.core import signing

    return signing.signing_secret(str(row["id"]))


def _require_signing_available(wanted: bool) -> None:
    """Fail before a key is minted, not after."""
    if not wanted:
        return
    from app.core import signing

    try:
        signing.signing_secret("availability-check")
    except signing.SignatureError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail={"error": exc.code, "message": exc.message}) from exc


class RotateBody(BaseModel):
    grace_hours: int = Field(default=24, ge=0, le=720, description="How long the old key keeps working so collectors can be updated.")


@router.post("/{key_id}/rotate", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED,
             summary="Issue a replacement key; the old key stays valid for the grace period")
def rotate_key(key_id: str, body: RotateBody, user: Annotated[CurrentUser, Depends(require_admin)]) -> ApiKeyCreated:
    if user.auth_method != "jwt":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot rotate API keys.")
    out = api_key_service.rotate_api_key(user.organization_id, key_id, grace_hours=body.grace_hours, created_by=user.id)
    if out is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found or already revoked.")
    row, raw, old = out
    secret = _signing_secret_or_none(row, bool(row.get("require_signature")))
    case_service.audit(
        user, action="api_key.rotated", target_type="api_key", row={"id": row["id"], "title": row["name"]},
        changes={"replaces": key_id, "old_key_valid_until": old["expires_at"], "grace_hours": body.grace_hours}, severity="high",
    )
    return ApiKeyCreated(**{**row, "created_at": str(row["created_at"])}, api_key=raw, signing_secret=secret)


@router.get("", response_model=ApiKeyList)
def list_keys(user: Annotated[CurrentUser, Depends(require_admin)]) -> ApiKeyList:
    rows = api_key_service.list_api_keys(user.organization_id)
    return ApiKeyList(items=[ApiKeyItem(**{**r, "created_at": str(r["created_at"])}) for r in rows])


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response, response_model=None)
def revoke_key(key_id: str, user: Annotated[CurrentUser, Depends(require_admin)]) -> Response:
    row = api_key_service.revoke_api_key(user.organization_id, key_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found or already revoked.")
    case_service.audit(
        user, action="api_key.revoked", target_type="api_key",
        row={"id": key_id, "title": row.get("name")}, changes={}, severity="high",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
