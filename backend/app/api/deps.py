from __future__ import annotations

from typing import Annotated, Literal, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.core.logging import bind_request_context, get_logger
from app.core.security import (
    AuthError,
    TokenClaims,
    decode_supabase_jwt,
    extract_bearer_token,
)
from app.services import api_key_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

# Numeric tiers used for "minimum role required" comparisons.
ROLE_TIER: dict[str, int] = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "owner": 4,
}


class CurrentUser(BaseModel):
    """Merged identity object: JWT claims + DB profile, or an API-key principal.

    Endpoints accept this as ``user: CurrentUser = Depends(require_viewer)`` (or
    another ``require_*`` gate).
    """

    id: str = Field(..., description="auth.users id, or the API key id for machine principals.")
    email: Optional[str] = None
    access_token: str = Field(default="", description="Raw JWT (empty for API keys).")

    organization_id: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "viewer"
    status: str = "active"
    avatar_url: Optional[str] = None

    auth_method: Literal["jwt", "api_key"] = "jwt"
    scopes: list[str] = Field(default_factory=list)

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def is_admin(self) -> bool:
        return self.role in ("owner", "admin")

    @property
    def is_analyst(self) -> bool:
        return self.role in ("owner", "admin", "analyst")

    @property
    def display_name(self) -> str:
        return self.full_name or self.email or self.id

    def has_role(self, minimum: str) -> bool:
        return ROLE_TIER.get(self.role, 0) >= ROLE_TIER.get(minimum, 99)


def _auth_http_exception(err: AuthError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": err.error_code, "message": err.message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_bearer_token(
    authorization: Annotated[Optional[str], Header()] = None,
) -> str:
    """Pull the raw JWT out of ``Authorization: Bearer <token>``."""
    try:
        return extract_bearer_token(authorization)
    except AuthError as err:
        raise _auth_http_exception(err) from err


def get_token_claims(
    token: Annotated[str, Depends(get_bearer_token)],
) -> TokenClaims:
    """Verify signature/expiry and return the parsed claims."""
    try:
        return decode_supabase_jwt(token)
    except AuthError as err:
        raise _auth_http_exception(err) from err


def _principal_from_api_key(raw_key: str) -> CurrentUser:
    try:
        row = api_key_service.authenticate_api_key(raw_key)
    except Exception as exc:
        log.exception("api_key_lookup_failed")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "auth_unavailable", "message": "Could not verify the API key."},
        ) from exc
    if row is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_api_key", "message": "API key is invalid, expired or revoked."},
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return CurrentUser(
        id=str(row["id"]),
        full_name=f"API key: {row.get('name')}",
        organization_id=str(row["organization_id"]),
        role=row.get("role") or "analyst",
        auth_method="api_key",
        scopes=list(row.get("scopes") or []),
    )


def _principal_from_jwt(token: str) -> CurrentUser:
    try:
        claims = decode_supabase_jwt(token)
    except AuthError as err:
        raise _auth_http_exception(err) from err

    user_id = claims.user_id
    admin = get_supabase_admin()
    try:
        result = (
            admin.table("users")
            .select("organization_id, full_name, role, status, avatar_url, email, deleted_at")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        log.exception("user_profile_fetch_failed", user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "user_lookup_failed", "message": "Could not load your profile."},
        ) from exc

    rows = result.data or []
    if not rows:
        log.warning("user_profile_missing", user_id=user_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "user_not_provisioned",
                "message": (
                    "Authenticated but no matching profile row in public.users. "
                    "This usually means the signup trigger failed to run."
                ),
            },
        )

    row = rows[0]
    if row.get("deleted_at"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "user_deleted", "message": "This account has been deleted."},
        )
    if row.get("status") == "disabled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "user_disabled",
                "message": "This account is disabled. Contact your administrator.",
            },
        )

    return CurrentUser(
        id=user_id,
        email=row.get("email") or claims.email,
        access_token=token,
        organization_id=row.get("organization_id"),
        full_name=row.get("full_name") or claims.full_name,
        role=row.get("role") or "viewer",
        status=row.get("status") or "active",
        avatar_url=row.get("avatar_url"),
    )


def get_current_user(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header()] = None,
) -> CurrentUser:
    """Resolve the caller from ``X-API-Key`` or ``Authorization: Bearer <jwt>``.

    This does *not* require an organization; use the ``require_*`` gates for
    anything that touches tenant data.
    """
    if x_api_key:
        user = _principal_from_api_key(x_api_key.strip())
    else:
        try:
            token = extract_bearer_token(authorization)
        except AuthError as err:
            raise _auth_http_exception(err) from err
        user = _principal_from_jwt(token)

    request.state.user_id = user.id
    request.state.organization_id = user.organization_id
    bind_request_context(user_id=user.id, organization_id=user.organization_id)
    return user


def require_role(minimum: str, *, scope: str | None = None):
    """Gate an endpoint on a minimum role *and* a resolved organization.

    ``scope`` opts the endpoint in to API-key callers: a key may only call
    endpoints whose declared scope it holds. Human (JWT) callers ignore it.
    Endpoints without a scope are never reachable with an API key.
    """

    def _checker(
        user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        if not user.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "no_organization",
                    "message": "Your account is not assigned to any organization.",
                },
            )
        if user.auth_method == "api_key":
            if scope is None or scope not in user.scopes:
                log.warning("api_key_scope_denied", key_id=user.id, required_scope=scope)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "insufficient_scope",
                        "message": "This API key is not allowed to call this endpoint.",
                    },
                )
        if not user.has_role(minimum):
            log.warning(
                "role_check_failed",
                user_id=user.id,
                user_role=user.role,
                required_role=minimum,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_role",
                    "message": (
                        f"This action requires the '{minimum}' role or higher. "
                        f"Your role is '{user.role}'."
                    ),
                    "required_role": minimum,
                    "your_role": user.role,
                },
            )
        return user

    return _checker


# common role gates that most endpoints use
require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
require_owner = require_role("owner")

# machine-callable gates
require_ingest = require_role("analyst", scope="ingest")
require_executor_read = require_role("analyst", scope="executor")


__all__ = [
    "CurrentUser",
    "get_bearer_token",
    "get_token_claims",
    "get_current_user",
    "require_role",
    "require_viewer",
    "require_analyst",
    "require_admin",
    "require_owner",
    "require_ingest",
    "require_executor_read",
]
