"""The JWKS/OIDC path over REAL HTTP against a local identity provider.

VERIFIED HERE: the actual httpx fetch, caching, key rotation, outage, slowness, oversize and redirect handling, end to end through the API.
NOT VERIFIED HERE: any hosted IdP (Okta, Entra ID, Auth0, Supabase signing keys). This server is a test double that speaks the same protocol,
so TLS, vendor quirks and real key-rollover schedules are untested (docs/reports/deployment-verification.md).
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core import jwks
from app.core.config import get_settings
from tests.test_jwks_oidc import (  # noqa: F401  (fixtures: rsa_key via conftest-style import below)
    AUD,
    ISS,
    _api,
    _first_analyst_id,
    rsa_jwk,
    tok,
)


class IdP:
    def __init__(self) -> None:
        self.keys: list[dict] = []
        self.mode = "ok"            # ok | slow | huge | redirect | garbage | error
        self.hits = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):          # quiet
                pass

            def do_GET(self):               # noqa: N802
                outer.hits += 1
                if outer.mode == "slow":
                    time.sleep(7)
                if outer.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:9/evil")
                    self.end_headers()
                    return
                if outer.mode == "error":
                    self.send_response(503)
                    self.end_headers()
                    return
                body = (b"x" * 400_000) if outer.mode == "huge" else (b"not json" if outer.mode == "garbage" else json.dumps({"keys": outer.keys}).encode())
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/jwks.json"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture(scope="module")
def key_a():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def key_b():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def idp(monkeypatch, key_a):
    server = IdP()
    server.keys = [rsa_jwk(key_a, "a1")]
    s = get_settings()
    monkeypatch.setattr(s, "OIDC_ISSUER", ISS)
    monkeypatch.setattr(s, "OIDC_AUDIENCE", AUD)
    monkeypatch.setattr(s, "OIDC_JWKS_URL", server.url)
    monkeypatch.setattr(jwks, "MIN_REFRESH_SECONDS", 0.0)
    jwks.reset_cache()
    yield server
    server.stop()
    jwks.reset_cache()


def test_token_verified_with_keys_fetched_over_http_and_cached(client, db, idp, key_a):
    db.table("users").update({"email": "alice@example.com"}).eq("id", _first_analyst_id(db)).execute()
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 200
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 200
    assert idp.hits == 1                                   # second request served from the cache


def test_key_rotation_is_picked_up_without_a_restart(client, db, idp, key_a, key_b):
    db.table("users").update({"email": "alice@example.com"}).eq("id", _first_analyst_id(db)).execute()
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 200
    idp.keys = [rsa_jwk(key_a, "a1"), rsa_jwk(key_b, "b2")]               # the IdP publishes a new key alongside the old
    assert _api(client, tok(key_b, "RS256", "b2")).status_code == 200      # unknown kid -> refetch -> accepted
    idp.keys = [rsa_jwk(key_b, "b2")]                                      # the old key is retired
    jwks.reset_cache()
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 401      # a token signed by a retired key no longer works


def test_idp_outage_keeps_known_keys_working_but_never_trusts_unknown_ones(client, db, idp, key_a, key_b):
    db.table("users").update({"email": "alice@example.com"}).eq("id", _first_analyst_id(db)).execute()
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 200
    idp.mode = "error"
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 200              # cached
    assert _api(client, tok(key_b, "RS256", "b2")).status_code == 401              # unknown key during an outage fails closed


def test_cold_start_during_an_outage_fails_closed(client, db, idp, key_a):
    idp.mode = "error"
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 401


@pytest.mark.parametrize("mode", ["garbage", "huge", "redirect"])
def test_hostile_or_broken_jwks_responses_never_authenticate_anyone(client, db, idp, key_a, mode):
    idp.mode = mode
    assert _api(client, tok(key_a, "RS256", "a1")).status_code == 401


def test_a_slow_idp_cannot_hang_authentication(client, db, idp, key_a):
    idp.mode = "slow"
    t0 = time.monotonic()
    r = _api(client, tok(key_a, "RS256", "a1"))
    assert r.status_code == 401 and time.monotonic() - t0 < 6.5        # the 5 s fetch timeout bounds the request
