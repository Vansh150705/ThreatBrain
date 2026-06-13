from __future__ import annotations

from functools import lru_cache
from typing import Optional

from supabase import Client, create_client
from supabase.client import ClientOptions

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)



@lru_cache(maxsize=1)
def get_supabase_admin() -> Client:

    settings = get_settings()

    if not settings.SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "SUPABASE_SERVICE_ROLE_KEY is not configured. "
            "Cannot create admin client."
        )

    client = create_client(
        supabase_url=str(settings.SUPABASE_URL),
        supabase_key=settings.SUPABASE_SERVICE_ROLE_KEY,
        options=ClientOptions(
            auto_refresh_token=False,   # service-role keys don't refresh
            persist_session=False,      # never persist server-side
        ),
    )

    log.info(
        "supabase_admin_client_initialized",
        supabase_url=str(settings.SUPABASE_URL),
    )
    return client


def get_supabase_user(access_token: str) -> Client:

    settings = get_settings()

    client = create_client(
        supabase_url=str(settings.SUPABASE_URL),
        supabase_key=settings.SUPABASE_ANON_KEY,
        options=ClientOptions(
            auto_refresh_token=False,
            persist_session=False,
            headers={"Authorization": f"Bearer {access_token}"},
        ),
    )

    # Set the auth session so PostgREST receives the JWT on every query.
    # no refresh token here, the frontend handles that
    client.postgrest.auth(access_token)

    return client


def supabase_health_check() -> dict[str, object]:

    try:
        client = get_supabase_admin()
        result = (
            client.table("organizations")
            .select("id", count="exact")
            .limit(1)
            .execute()
        )

        return {
            "ok": True,
            "rows_visible": result.count if result.count is not None else 0,
        }
    except Exception as exc:  # noqa: BLE001  broad catch is fine in a health check
        log.error(
            "supabase_health_check_failed",
            exception_type=type(exc).__name__,
            exception_message=str(exc),
        )
        return {"ok": False, "error": str(exc)}


__all__ = [
    "Client",
    "get_supabase_admin",
    "get_supabase_user",
    "supabase_health_check",
]