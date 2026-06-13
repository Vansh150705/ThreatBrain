from __future__ import annotations

from typing import Any, Optional

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
)
from pydantic import BaseModel, EmailStr, Field

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

class AuthError(Exception):
    """Base class for all authentication failures."""

    status_code: int = 401
    error_code: str = "auth_error"

    def __init__(self, message: str = "Authentication failed."):
        super().__init__(message)
        self.message = message


class MissingTokenError(AuthError):
    error_code = "missing_token"

    def __init__(self) -> None:
        super().__init__("Authorization header is missing or malformed.")


class ExpiredTokenError(AuthError):
    error_code = "expired_token"

    def __init__(self) -> None:
        super().__init__("Access token has expired.")


class InvalidTokenSignatureError(AuthError):
    error_code = "invalid_signature"

    def __init__(self) -> None:
        super().__init__("Token signature is invalid.")


class MalformedTokenError(AuthError):
    error_code = "malformed_token"

    def __init__(self, detail: str = "") -> None:
        super().__init__(f"Token is malformed. {detail}".strip())


class TokenClaims(BaseModel):

    sub: str = Field(..., description="Supabase user UUID")
    email: Optional[EmailStr] = None
    aud: str
    role: str = "authenticated"
    iss: Optional[str] = None
    exp: int
    iat: int
    user_metadata: dict[str, Any] = Field(default_factory=dict)
    app_metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def user_id(self) -> str:
        """Alias for sub, matches the column name in our users table."""
        return self.sub

    @property
    def full_name(self) -> Optional[str]:
        return self.user_metadata.get("full_name")

    @property
    def organization_id_hint(self) -> Optional[str]:
        """Org hint stored in user_metadata at signup. Authoritative
        org membership still comes from `public.users.organization_id`."""
        return self.user_metadata.get("organization_id")

def decode_supabase_jwt(
    token: str,
    *,
    verify_signature: bool = True,
    verify_exp: bool = True,
) -> TokenClaims:

    if not token:
        raise MissingTokenError()

    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            key=settings.SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
            leeway=30,
            options={
                "verify_signature": verify_signature,
                "verify_exp": verify_exp,
                "verify_aud": True,
                "require": ["sub", "exp", "iat", "aud"],
            },
        )
    except ExpiredSignatureError as exc:
        log.warning("jwt_expired")
        raise ExpiredTokenError() from exc
    except InvalidSignatureError as exc:
        log.warning("jwt_invalid_signature")
        raise InvalidTokenSignatureError() from exc
    except (InvalidAudienceError, InvalidIssuerError) as exc:
        log.warning("jwt_invalid_claim", error=str(exc))
        raise MalformedTokenError(str(exc)) from exc
    except InvalidTokenError as exc:
        log.warning("jwt_malformed", error=str(exc))
        raise MalformedTokenError(str(exc)) from exc
    except Exception as exc:
        log.exception("jwt_decode_unexpected_error")
        raise AuthError(f"Unexpected token error: {exc}") from exc

    try:
        return TokenClaims.model_validate(payload)
    except Exception as exc:
        log.warning("jwt_claims_validation_failed", error=str(exc))
        raise MalformedTokenError("Token payload missing required claims.") from exc


def extract_bearer_token(authorization_header: Optional[str]) -> str:
    """Pull the JWT out of an ``Authorization: Bearer <token>`` header.

    Raises ``MissingTokenError`` if the header is absent or malformed.
    """
    if not authorization_header:
        raise MissingTokenError()

    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise MissingTokenError()

    token = parts[1].strip()
    if not token:
        raise MissingTokenError()

    return token


__all__ = [
    "AuthError",
    "MissingTokenError",
    "ExpiredTokenError",
    "InvalidTokenSignatureError",
    "MalformedTokenError",
    "TokenClaims",
    "decode_supabase_jwt",
    "extract_bearer_token",
]