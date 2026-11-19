"""The database client must use HTTP/1.1. supabase-py defaults to one shared HTTP/2 connection, which fails in a few percent of
calls when many threads use it at once (RemoteProtocolError / ConnectionTerminated), seen as random 500s under parallel load."""

from __future__ import annotations

from supabase import create_client
from supabase.client import ClientOptions

from app.services import supabase_client

# Looks like a JWT so supabase-py accepts it; never sent anywhere.
FAKE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2ln"


def _client():
    return create_client("http://localhost:54321", FAKE_KEY, options=ClientOptions(auto_refresh_token=False, persist_session=False))


def test_library_default_is_http2_which_is_why_we_override_it():
    assert _client().postgrest.session._transport._pool._http2 is True


def test_use_http1_replaces_the_pool_and_keeps_the_request_settings():
    client = _client()
    old = client.postgrest.session
    out = supabase_client._use_http1(client)
    new = client.postgrest.session
    assert out is client and new is not old
    assert new._transport._pool._http2 is False
    assert str(new.base_url) == str(old.base_url)
    assert new.headers["apikey"] == FAKE_KEY and new.timeout == old.timeout
    assert new.follow_redirects is True


def test_token_auth_still_reaches_the_new_session():
    client = supabase_client._use_http1(_client())
    client.postgrest.auth("user-jwt")
    assert client.postgrest.session.headers["authorization"] == "Bearer user-jwt"


def test_admin_and_user_clients_are_built_on_http1(monkeypatch):
    monkeypatch.setattr(supabase_client, "create_client", lambda **kw: _client())
    settings = supabase_client.get_settings()
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", FAKE_KEY)
    supabase_client.get_supabase_admin.cache_clear()
    try:
        assert supabase_client.get_supabase_admin().postgrest.session._transport._pool._http2 is False
        assert supabase_client.get_supabase_user("tok").postgrest.session._transport._pool._http2 is False
    finally:
        supabase_client.get_supabase_admin.cache_clear()


def test_clients_without_an_httpx_session_are_left_alone():
    class Double:
        postgrest = None

    d = Double()
    assert supabase_client._use_http1(d) is d  # type: ignore[arg-type]
