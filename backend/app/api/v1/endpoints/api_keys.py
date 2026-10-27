"""Machine credentials for collectors, executors and webhooks (admin only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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


class ApiKeyCreated(ApiKeyItem):
    api_key: str = Field(description="Shown once. Store it in your secret manager; it cannot be retrieved later.")


class ApiKeyList(BaseModel):
    items: list[ApiKeyItem]


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(body: ApiKeyCreate, user: Annotated[CurrentUser, Depends(require_admin)]) -> ApiKeyCreated:
    if user.auth_method != "jwt":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot mint other API keys.")
    expires = (
        (datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)).isoformat()
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
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    case_service.audit(
        user, action="api_key.created", target_type="api_key",
        row={"id": row["id"], "title": body.name}, changes={"scopes": body.scopes, "expires_at": expires},
        severity="high",
    )
    return ApiKeyCreated(**{**row, "created_at": str(row["created_at"])}, api_key=raw)


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
