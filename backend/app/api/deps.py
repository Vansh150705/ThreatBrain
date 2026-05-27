from __future__ import annotations

from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from app.core.logging import get_logger
from app.core.security import (
    AuthError,
    TokenClaims,
    decode_supabase_jwt,
    extract_bearer_token,
)
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
    """Merged identity object: JWT claims + DB profile.

    Endpoints accept this as ``user: CurrentUser = Depends(get_current_user)``.
    """

    # From JWT
    id: str = Field(..., description="UUID from JWT `sub` claim (matches auth.users.id).")
    email: Optional[EmailStr] = None
    access_token: str = Field(..., description="Raw JWT for use in get_supabase_user().")

    # From public.users profile
    organization_id: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "viewer"
    status: str = "active"
    avatar_url: Optional[str] = None

    # Convenience helpers
    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def is_admin(self) -> bool:
        return self.role in ("owner", "admin")

    @property
    def is_analyst(self) -> bool:
        return self.role in ("owner", "admin", "analyst")

    def has_role(self, minimum: str) -> bool:
        return ROLE_TIER.get(self.role, 0) >= ROLE_TIER.get(minimum, 99)


def _auth_http_exception(err: AuthError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": err.error_code,
            "message": err.message,
        },
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


def get_current_user(
    request: Request,
    token: Annotated[str, Depends(get_bearer_token)],
    claims: Annotated[TokenClaims, Depends(get_token_claims)],
) -> CurrentUser:
    """Resolve the full ``CurrentUser`` for a request.

    Combines verified JWT claims with the user's row from
    ``public.users`` so we have the user's organization_id and role
    available everywhere.
    """
    user_id = claims.user_id

    # Fetch profile via service-role client (bypasses RLS).
    # We then re-attach the user's JWT to per-request DB calls
    # downstream, where RLS *should* apply.
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
            detail={"error": "user_lookup_failed", "message": str(exc)},
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
            detail={
                "error": "user_deleted",
                "message": "This account has been deleted.",
            },
        )

    if row.get("status") == "disabled":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "user_disabled",
                "message": "This account is disabled. Contact your administrator.",
            },
        )

    user = CurrentUser(
        id=user_id,
        email=row.get("email") or claims.email,
        access_token=token,
        organization_id=row.get("organization_id"),
        full_name=row.get("full_name") or claims.full_name,
        role=row.get("role") or "viewer",
        status=row.get("status") or "active",
        avatar_url=row.get("avatar_url"),
    )

    # Stash the user_id on the request state in case middleware/logs want it
    request.state.user_id = user.id
    request.state.organization_id = user.organization_id

    return user


def require_role(minimum: str):


    def _checker(
        user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
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


# Pre-built role gates — most endpoints use these
require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
require_owner = require_role("owner")


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
]