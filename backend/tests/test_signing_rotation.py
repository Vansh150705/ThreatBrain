"""Signed + replay-protected ingestion, API-key rotation and usage tracking."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from app.core import signing
from app.core.config import get_settings
from tests.conftest import ORG_A

EV = {"event": {"title": "Process creation", "event_type": "process.start", "command_line": "vssadmin delete shadows /all",
                "asset_name": "srv-1", "occurred_at": "2026-01-01T10:00:00Z"}}
PATH = "/api/v1/ingest/event"


@pytest.fixture()
def secret(monkeypatch):
    monkeypatch.setattr(get_settings(), "APP_SECRET", "x" * 48)


def make_key(client, auth, **body):
    r = client.post("/api/v1/api-keys", json={"name": "collector", "scopes": ["ingest"], **body}, headers=auth("admin_a"))
    assert r.status_code == 201, r.text
    return r.json()


def signed(client, key, payload=EV, *, ts=None, path=PATH, method="POST", secret_=None, body_override=None):
    body = json.dumps(payload).encode()
    ts = str(ts if ts is not None else int(time.time()))
    sig = signing.sign(secret_ or key["signing_secret"], ts, method, path, body)
    headers = {"X-API-Key": key["api_key"], "X-TB-Timestamp": ts, "X-TB-Signature": sig, "Content-Type": "application/json"}
    return client.post(path, content=body_override if body_override is not None else body, headers=headers)


def test_creating_a_signed_key_requires_app_secret(client, auth, monkeypatch):
    monkeypatch.setattr(get_settings(), "APP_SECRET", "")
    r = client.post("/api/v1/api-keys", json={"name": "c", "scopes": ["ingest"], "require_signature": True}, headers=auth("admin_a"))
    assert r.status_code == 409 and r.json()["detail"]["error"] == "signing_unavailable"
    assert client.get("/api/v1/api-keys", headers=auth("admin_a")).json()["items"] == []  # no half-created key


def test_valid_signature_accepted_and_secret_is_shown_once(client, auth, secret):
    key = make_key(client, auth, require_signature=True)
    assert key["signing_secret"] and key["require_signature"] is True
    assert signed(client, key).status_code == 200
    listed = client.get("/api/v1/api-keys", headers=auth("admin_a")).json()["items"][0]
    assert "signing_secret" not in listed and "api_key" not in listed


def test_unsigned_request_with_signed_key_rejected(client, auth, secret):
    key = make_key(client, auth, require_signature=True)
    r = client.post(PATH, json=EV, headers={"X-API-Key": key["api_key"]})
    assert r.status_code == 401 and r.json()["detail"]["error"] == "signature_required"


@pytest.mark.parametrize("case", ["tampered_body", "wrong_path", "wrong_method_secret", "stale", "future", "garbage_ts", "wrong_secret"])
def test_signature_failures(client, auth, secret, case):
    key = make_key(client, auth, require_signature=True)
    if case == "tampered_body":
        evil = {"event": {**EV["event"], "command_line": "echo harmless"}}
        body = json.dumps(EV).encode()
        ts = str(int(time.time()))
        sig = signing.sign(key["signing_secret"], ts, "POST", PATH, body)
        r = client.post(PATH, content=json.dumps(evil).encode(),
                        headers={"X-API-Key": key["api_key"], "X-TB-Timestamp": ts, "X-TB-Signature": sig, "Content-Type": "application/json"})
    elif case == "wrong_path":
        body = json.dumps(EV).encode()
        ts = str(int(time.time()))
        sig = signing.sign(key["signing_secret"], ts, "POST", "/api/v1/ingest/events", body)
        r = client.post(PATH, content=body, headers={"X-API-Key": key["api_key"], "X-TB-Timestamp": ts, "X-TB-Signature": sig,
                                                      "Content-Type": "application/json"})
    elif case == "wrong_method_secret":
        r = signed(client, key, method="PUT")
    elif case == "stale":
        r = signed(client, key, ts=int(time.time()) - 3600)
    elif case == "future":
        r = signed(client, key, ts=int(time.time()) + 3600)
    elif case == "garbage_ts":
        r = signed(client, key, ts="yesterday")
    else:
        r = signed(client, key, secret_="0" * 64)
    assert r.status_code in (401, 405), (case, r.status_code, r.text)
    assert r.status_code != 200


def test_replayed_request_is_refused(client, auth, secret, db):
    key = make_key(client, auth, require_signature=True)
    ts = int(time.time())
    first = signed(client, key, ts=ts)
    again = signed(client, key, ts=ts)
    assert first.status_code == 200
    assert again.status_code == 409 and again.json()["detail"]["error"] == "replayed_request"
    assert len(db.rows("replay_guard")) == 1


def test_a_signature_for_one_key_is_useless_for_another(client, auth, secret):
    a, b = make_key(client, auth, require_signature=True), make_key(client, auth, require_signature=True)
    r = signed(client, b, secret_=a["signing_secret"])
    assert r.status_code == 401


def test_keys_without_the_flag_are_unaffected(client, auth, secret):
    key = make_key(client, auth)
    assert key["signing_secret"] is None
    assert client.post(PATH, json=EV, headers={"X-API-Key": key["api_key"]}).status_code == 200


def test_replay_guard_failure_fails_closed(client, auth, secret, monkeypatch):
    from app.services import api_key_service

    key = make_key(client, auth, require_signature=True)
    real = api_key_service.get_supabase_admin()

    class Proxy:
        def table(self, name):
            if name == "replay_guard":
                raise RuntimeError("replay table unavailable")
            return real.table(name)

    monkeypatch.setattr(api_key_service, "get_supabase_admin", lambda: Proxy())
    r = signed(client, key)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "replay_guard_unavailable"  # never accepted unprotected


# ---------------------------------------------------------------- rotation + usage
def test_rotation_keeps_old_key_for_grace_then_it_expires(client, auth, secret, db):
    old = make_key(client, auth)
    r = client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={"grace_hours": 2}, headers=auth("admin_a"))
    assert r.status_code == 201
    new = r.json()
    assert new["api_key"] != old["api_key"] and new["rotated_from"] == old["id"] and new["scopes"] == ["ingest"]
    assert client.post(PATH, json=EV, headers={"X-API-Key": old["api_key"]}).status_code == 200   # grace
    assert client.post(PATH, json=EV, headers={"X-API-Key": new["api_key"]}).status_code == 200
    row = next(k for k in db.rows("api_keys") if k["id"] == old["id"])
    exp = datetime.fromisoformat(str(row["expires_at"]))
    assert timedelta(hours=1, minutes=50) < exp - datetime.now(UTC) < timedelta(hours=2, minutes=1)
    row["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()                    # grace over
    assert client.post(PATH, json=EV, headers={"X-API-Key": old["api_key"]}).status_code == 401
    assert client.post(PATH, json=EV, headers={"X-API-Key": new["api_key"]}).status_code == 200


def test_rotation_with_zero_grace_cuts_over_immediately(client, auth, secret):
    old = make_key(client, auth)
    client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={"grace_hours": 0}, headers=auth("admin_a"))
    assert client.post(PATH, json=EV, headers={"X-API-Key": old["api_key"]}).status_code == 401


def test_rotation_preserves_signing_policy_and_issues_a_new_secret(client, auth, secret):
    old = make_key(client, auth, require_signature=True)
    new = client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers=auth("admin_a")).json()
    assert new["require_signature"] and new["signing_secret"] and new["signing_secret"] != old["signing_secret"]
    assert signed(client, new).status_code == 200


def test_rotation_authorization_and_isolation(client, auth, secret):
    old = make_key(client, auth)
    assert client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers=auth("analyst_a")).status_code == 403
    assert client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers=auth("owner_b")).status_code == 404
    assert client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers={"X-API-Key": old["api_key"]}).status_code in (401, 403)
    client.delete(f"/api/v1/api-keys/{old['id']}", headers=auth("admin_a"))
    assert client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers=auth("admin_a")).status_code == 404


def test_usage_is_recorded_per_key(client, auth, db):
    key = make_key(client, auth)
    client.post(PATH, json=EV, headers={"X-API-Key": key["api_key"]})
    row = next(k for k in db.rows("api_keys") if k["id"] == key["id"])
    assert row["last_used_at"] and row["use_count"] >= 1 and row["last_used_ip"]
    listed = client.get("/api/v1/api-keys", headers=auth("admin_a")).json()["items"][0]
    assert listed["use_count"] >= 1 and listed["last_used_ip"]
    assert any(a["action"] == "api_key.created" for a in db.rows("audit_logs", organization_id=ORG_A))


def test_rotation_is_audited(client, auth, secret, db):
    old = make_key(client, auth)
    client.post(f"/api/v1/api-keys/{old['id']}/rotate", json={}, headers=auth("admin_a"))
    assert any(a["action"] == "api_key.rotated" for a in db.rows("audit_logs", organization_id=ORG_A))
