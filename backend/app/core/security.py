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
from pydantic import BaseModel, Field

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
    email: Optional[str] = None
    aud: str
    role: str = "authenticated"
    iss: Optional[str] = None
    exp: int
    iat: int
    user_metadata: dict[str, Any] = Field(default_factory=dict)
    app_metadata: dict[str, Any] = Field(default_factory=dict)
    external: bool = False           # issued by the configured OIDC IdP rather than Supabase
    email_verified: bool = False

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

_SUPABASE_ASYMMETRIC = {"ES256", "RS256"}


def _verify(token: str, key: Any, algs: list[str], audience: str, issuer: str | None) -> dict[str, Any]:
    return jwt.decode(
        token,
        key=key,
        algorithms=algs,
        audience=audience,
        issuer=issuer,
        leeway=30,
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": issuer is not None,
            "require": ["sub", "exp", "iat", "aud"],
        },
    )


def _select_and_verify(token: str) -> tuple[dict[str, Any], bool]:
    """Pick the one verification path the token's header + issuer allow. Returns (payload, external_idp).

    The algorithm is decided by *us* from configuration, never trusted from the header alone:
    HS256 can only be checked against the Supabase secret; an asymmetric token can only be checked
    against a JWKS public key, so a public key can never be abused as an HMAC secret.
    """
    from app.core import jwks

    settings = get_settings()
    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
    except InvalidTokenError as exc:
        raise MalformedTokenError() from exc
    alg = header.get("alg")

    if alg == "HS256":
        return _verify(token, settings.SUPABASE_JWT_SECRET, ["HS256"], "authenticated", None), False

    iss = unverified.get("iss")
    if settings.OIDC_ISSUER and iss == settings.OIDC_ISSUER:
        allowed = {a.strip() for a in settings.OIDC_ALLOWED_ALGS.split(",") if a.strip()} - {"none", "HS256", "HS384", "HS512"}
        if alg not in allowed:
            raise MalformedTokenError("Algorithm not allowed.")
        url = settings.OIDC_JWKS_URL or settings.OIDC_ISSUER.rstrip("/") + "/.well-known/jwks.json"
        try:
            key = jwks.get_signing_key(url, header.get("kid"), allowed)
        except jwks.JWKSError as exc:
            log.warning("oidc_key_unavailable", error=str(exc))
            raise InvalidTokenSignatureError() from exc
        return _verify(token, key, [alg], settings.OIDC_AUDIENCE, settings.OIDC_ISSUER), True

    if alg in _SUPABASE_ASYMMETRIC:
        base = str(settings.SUPABASE_URL).rstrip("/")
        if not (isinstance(iss, str) and iss.startswith(base)):
            raise MalformedTokenError("Unexpected issuer.")
        url = settings.SUPABASE_JWKS_URL or f"{base}/auth/v1/.well-known/jwks.json"
        try:
            key = jwks.get_signing_key(url, header.get("kid"), _SUPABASE_ASYMMETRIC)
        except jwks.JWKSError as exc:
            log.warning("supabase_key_unavailable", error=str(exc))
            raise InvalidTokenSignatureError() from exc
        return _verify(token, key, [alg], "authenticated", None), False

    raise MalformedTokenError("Unsupported token algorithm.")


def decode_supabase_jwt(token: str) -> TokenClaims:
    """Verify an access token (signature, expiry, audience) and parse it.

    Supabase HS256 tokens, Supabase asymmetric signing keys (JWKS) and, when configured, tokens from an
    external OIDC IdP are accepted. Signature and expiry verification are not optional: there is
    deliberately no flag to turn them off.
    """
    if not token:
        raise MissingTokenError()

    settings = get_settings()

    try:
        payload, external = _select_and_verify(token)
    except ExpiredSignatureError as exc:
        log.warning("jwt_expired")
        raise ExpiredTokenError() from exc
    except InvalidSignatureError as exc:
        log.warning("jwt_invalid_signature")
        raise InvalidTokenSignatureError() from exc
    except (InvalidAudienceError, InvalidIssuerError) as exc:
        log.warning("jwt_invalid_claim", error=str(exc))
        raise MalformedTokenError("Invalid audience or issuer.") from exc
    except AuthError:
        raise
    except InvalidTokenError as exc:
        log.warning("jwt_malformed", error=str(exc))
        raise MalformedTokenError() from exc
    except Exception as exc:
        log.exception("jwt_decode_unexpected_error")
        raise AuthError("Token could not be verified.") from exc

    max_age = settings.MAX_TOKEN_AGE_MINUTES
    if max_age > 0:
        import time

        if time.time() - int(payload.get("iat", 0)) > max_age * 60 + 30:
            log.warning("jwt_too_old", max_age_minutes=max_age)
            raise ExpiredTokenError()

    try:
        claims = TokenClaims.model_validate(payload)
    except Exception as exc:
        log.warning("jwt_claims_validation_failed", error=str(exc))
        raise MalformedTokenError("Token payload missing required claims.") from exc
    claims.external = external
    claims.email_verified = bool(payload.get("email_verified") or (payload.get("user_metadata") or {}).get("email_verified"))
    return claims


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
