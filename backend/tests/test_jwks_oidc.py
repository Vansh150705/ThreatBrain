"""Asymmetric JWT verification (Supabase JWKS, external OIDC IdP).

VERIFIED HERE: the verification logic against keys generated locally. NOT verified here: any live
Supabase or IdP JWKS endpoint (the HTTP fetch is replaced by a stub).
"""

from __future__ import annotations

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.core import jwks
from app.core.config import get_settings
from tests.conftest import JWT_SECRET, ORG_A

ISS = "https://idp.example.com"
AUD = "threatbrain"
SUPA = "http://localhost:54321"


def _b64(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def rsa_jwk(key, kid="k1"):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64(n.n), "e": _b64(n.e)}


def ec_jwk(key, kid="e1"):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256", "x": _b64(n.x), "y": _b64(n.y)}


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def tok(key, alg, kid, **over):
    now = int(time.time())
    claims = {"sub": "u-ext-1", "aud": AUD, "iss": ISS, "iat": now, "exp": now + 600,
              "email": "alice@example.com", "email_verified": True, **over}
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, pem(key), algorithm=alg, headers={"kid": kid})


@pytest.fixture()
def oidc(monkeypatch, rsa_key, ec_key):
    s = get_settings()
    monkeypatch.setattr(s, "OIDC_ISSUER", ISS)
    monkeypatch.setattr(s, "OIDC_AUDIENCE", AUD)
    monkeypatch.setattr(s, "OIDC_JWKS_URL", f"{ISS}/jwks.json")
    monkeypatch.setattr(s, "SUPABASE_JWKS_URL", f"{SUPA}/auth/v1/.well-known/jwks.json")
    served = {f"{ISS}/jwks.json": {"keys": [rsa_jwk(rsa_key)]},
              f"{SUPA}/auth/v1/.well-known/jwks.json": {"keys": [ec_jwk(ec_key)]}}
    calls = []

    def fake_get(url):
        calls.append(url)
        if url not in served:
            raise RuntimeError("unreachable")
        return served[url]

    monkeypatch.setattr(jwks, "_http_get_json", fake_get)
    jwks.reset_cache()
    yield served, calls
    jwks.reset_cache()


def decode(t):
    from app.core.security import decode_supabase_jwt

    return decode_supabase_jwt(t)


def test_valid_oidc_token_accepted(oidc, rsa_key):
    c = decode(tok(rsa_key, "RS256", "k1"))
    assert c.external and c.email == "alice@example.com" and c.email_verified


def test_valid_supabase_es256_token_accepted(oidc, ec_key):
    c = decode(tok(ec_key, "ES256", "e1", iss=f"{SUPA}/auth/v1", aud="authenticated"))
    assert not c.external


@pytest.mark.parametrize("over,why", [
    ({"aud": "someone-else"}, "wrong audience"),
    ({"iss": "https://evil.example.com"}, "wrong issuer"),
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, "expired"),
])
def test_oidc_claim_failures_rejected(oidc, rsa_key, over, why):
    from app.core.security import AuthError

    with pytest.raises(AuthError):
        decode(tok(rsa_key, "RS256", "k1", **over))


def test_unknown_kid_and_wrong_signer_rejected(oidc, rsa_key):
    from app.core.security import AuthError

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthError):
        decode(tok(rsa_key, "RS256", "does-not-exist"))
    with pytest.raises(AuthError):
        decode(tok(other, "RS256", "k1"))  # right kid, signed by someone else


def test_algorithm_none_is_rejected(oidc):
    from app.core.security import AuthError

    now = int(time.time())
    payload = {"sub": "x", "aud": AUD, "iss": ISS, "iat": now, "exp": now + 600, "email": "a@example.com"}
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    forged = f"{b({'alg': 'none', 'typ': 'JWT', 'kid': 'k1'})}.{b(payload)}."
    with pytest.raises(AuthError):
        decode(forged)


def test_hs256_signed_with_the_public_key_is_rejected(oidc, rsa_key):
    """Classic algorithm-confusion attack: sign with HS256 using the public key as the HMAC secret."""
    from app.core.security import AuthError

    pub_pem = rsa_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    # PyJWT refuses to build this token itself, so build it by hand
    import hashlib
    import hmac

    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    head = b({"alg": "HS256", "typ": "JWT", "kid": "k1"})
    body = b({"sub": "x", "aud": AUD, "iss": ISS, "iat": now, "exp": now + 600, "email": "alice@example.com"})
    sig = base64.urlsafe_b64encode(hmac.new(pub_pem, f"{head}.{body}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    with pytest.raises(AuthError):
        decode(f"{head}.{body}.{sig}")


def test_hs256_with_the_wrong_secret_still_rejected(oidc):
    from app.core.security import AuthError

    now = int(time.time())
    t = jwt.encode({"sub": "x", "aud": "authenticated", "iat": now, "exp": now + 60}, "not-the-secret-not-the-secret-123456", algorithm="HS256")
    with pytest.raises(AuthError):
        decode(t)
    good = jwt.encode({"sub": "x", "aud": "authenticated", "iat": now, "exp": now + 60}, JWT_SECRET, algorithm="HS256")
    assert decode(good).sub == "x"


def test_asymmetric_token_from_unconfigured_issuer_rejected(monkeypatch, rsa_key):
    from app.core.security import AuthError

    s = get_settings()
    monkeypatch.setattr(s, "OIDC_ISSUER", "")
    with pytest.raises(AuthError):
        decode(tok(rsa_key, "RS256", "k1"))


def test_jwks_cached_and_stale_keys_survive_an_outage(oidc, rsa_key, monkeypatch):
    served, calls = oidc
    decode(tok(rsa_key, "RS256", "k1"))
    decode(tok(rsa_key, "RS256", "k1"))
    assert len(calls) == 1                                      # cached
    jwks._cache[f"{ISS}/jwks.json"] = (time.monotonic() - 10_000, jwks._cache[f"{ISS}/jwks.json"][1])  # expire
    served.clear()                                              # IdP down
    assert decode(tok(rsa_key, "RS256", "k1")).external         # stale keys keep existing sessions alive


def test_unknown_kid_refetch_is_rate_limited(oidc, rsa_key):
    from app.core.security import AuthError

    _, calls = oidc
    decode(tok(rsa_key, "RS256", "k1"))
    n = len(calls)
    for _ in range(5):
        with pytest.raises(AuthError):
            decode(tok(rsa_key, "RS256", "forged-kid"))
    assert len(calls) == n                                      # attacker cannot make us hammer the IdP


def test_max_token_age_enforced(monkeypatch):
    from app.core.security import ExpiredTokenError

    monkeypatch.setattr(get_settings(), "MAX_TOKEN_AGE_MINUTES", 10)
    now = int(time.time())
    old = jwt.encode({"sub": "x", "aud": "authenticated", "iat": now - 3600, "exp": now + 3600}, JWT_SECRET, algorithm="HS256")
    with pytest.raises(ExpiredTokenError):
        decode(old)


# -------- end to end through the API: external identities map to provisioned users by verified email only
def _api(client, token):
    return client.get("/api/v1/organizations/me", headers={"Authorization": f"Bearer {token}"})


def test_oidc_user_maps_by_verified_email_to_provisioned_user(client, db, oidc, rsa_key):
    db.table("users").update({"email": "alice@example.com"}).eq("id", _first_analyst_id(db)).execute()
    assert _api(client, tok(rsa_key, "RS256", "k1")).status_code == 200


def test_oidc_unverified_email_or_unknown_user_refused(client, db, oidc, rsa_key):
    db.table("users").update({"email": "alice@example.com"}).eq("id", _first_analyst_id(db)).execute()
    assert _api(client, tok(rsa_key, "RS256", "k1", email_verified=False)).status_code == 403
    assert _api(client, tok(rsa_key, "RS256", "k1", email="stranger@example.com")).status_code == 403


def _first_analyst_id(db):
    return next(u["id"] for u in db.rows("users") if u["role"] == "analyst" and u["organization_id"] == ORG_A)
