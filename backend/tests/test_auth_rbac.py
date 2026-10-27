"""Authentication, role gates, API keys and tenant isolation."""

from __future__ import annotations

import time
from datetime import UTC

import jwt

from tests.conftest import ORG_A, ORG_B, make_token


def _threat(db, org, **kw):
    row = {"organization_id": org, "title": "t", "severity": "high", "status": "open", "source_ips": ["203.0.113.9"]}
    row.update(kw)
    return db.table("threats").insert(row).execute().data[0]


# ------------------------------------------------------------------ JWT ----
def test_missing_and_malformed_tokens(client):
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_wrong_signature_expired_and_wrong_audience_rejected(client, users):
    uid = users["analyst_a"]
    bad_sig = make_token(uid, secret="x" * 40)
    expired = make_token(uid, exp_in=-3600)
    bad_aud = make_token(uid, aud="anon")
    for tok in (bad_sig, expired, bad_aud):
        r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 401, tok
        assert "error" in r.json()["detail"]


def test_alg_none_token_rejected(client, users):
    now = int(time.time())
    forged = jwt.encode({"sub": users["owner_a"], "aud": "authenticated", "iat": now, "exp": now + 99}, key="", algorithm="none")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_valid_token_resolves_profile_and_org(client, auth):
    r = client.get("/api/v1/me", headers=auth("analyst_a"))
    assert r.status_code == 200
    assert r.json()["role"] == "analyst" and r.json()["organization_id"] == ORG_A


def test_disabled_and_unprovisioned_users_blocked(client, db, users, auth):
    db.table("users").update({"status": "disabled"}).eq("id", users["viewer_a"]).execute()
    assert client.get("/api/v1/me", headers=auth("viewer_a")).status_code == 403
    ghost = make_token("11111111-1111-1111-1111-111111111111")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {ghost}"}).status_code == 403


def test_user_without_organization_gets_403_not_500(client, db, users, auth):
    db.table("users").update({"organization_id": None}).eq("id", users["analyst_a"]).execute()
    for path in ("/api/v1/threats", "/api/v1/incidents", "/api/v1/stats/dashboard", "/api/v1/audit",
                 "/api/v1/playbooks/approvals", "/api/v1/agents"):
        r = client.get(path, headers=auth("analyst_a"))
        assert r.status_code == 403, path
        assert r.json()["detail"]["error"] == "no_organization"


# ----------------------------------------------------------------- RBAC ----
def test_role_matrix(client, auth):
    body = {"event": {"title": "x", "event_type": "t"}}
    assert client.post("/api/v1/orchestrator/handle-event", json=body, headers=auth("viewer_a")).status_code == 403
    assert client.post("/api/v1/api-keys", json={"name": "k", "scopes": ["ingest"]}, headers=auth("analyst_a")).status_code == 403
    assert client.get("/api/v1/api-keys", headers=auth("analyst_a")).status_code == 403
    assert client.get("/api/v1/api-keys", headers=auth("admin_a")).status_code == 200
    assert client.get("/api/v1/threats", headers=auth("viewer_a")).status_code == 200
    assert client.get("/api/v1/organizations/members", headers=auth("viewer_a")).status_code == 403
    assert client.get("/api/v1/organizations/members", headers=auth("analyst_a")).status_code == 200


# ------------------------------------------------------ tenant isolation ----
def test_cross_tenant_reads_return_404(client, db, auth):
    a = _threat(db, ORG_A)
    inc = db.table("incidents").insert({"organization_id": ORG_A, "title": "i"}).execute().data[0]
    for path in (f"/api/v1/threats/{a['id']}", f"/api/v1/threats/{a['short_id']}",
                 f"/api/v1/incidents/{inc['id']}", f"/api/v1/incidents/{inc['short_id']}",
                 f"/api/v1/incidents/{inc['id']}/notes", f"/api/v1/incidents/{inc['id']}/timeline",
                 f"/api/v1/incidents/{inc['id']}/report"):
        assert client.get(path, headers=auth("owner_b")).status_code == 404, path
        assert client.get(path, headers=auth("owner_a")).status_code == 200, path


def test_cross_tenant_writes_blocked(client, db, auth):
    a = _threat(db, ORG_A)
    inc = db.table("incidents").insert({"organization_id": ORG_A, "title": "i"}).execute().data[0]
    assert client.patch(f"/api/v1/threats/{a['id']}", json={"status": "resolved"}, headers=auth("owner_b")).status_code == 404
    assert client.patch(f"/api/v1/incidents/{inc['id']}", json={"status": "closed"}, headers=auth("owner_b")).status_code == 404
    assert client.post(f"/api/v1/incidents/{inc['id']}/notes", json={"body": "x"}, headers=auth("owner_b")).status_code == 404
    assert db.rows("threats", id=a["id"])[0]["status"] == "open"


def test_list_endpoints_only_return_own_org(client, db, auth):
    _threat(db, ORG_A, title="mine")
    _threat(db, ORG_B, title="theirs")
    items = client.get("/api/v1/threats", headers=auth("analyst_a")).json()["items"]
    assert [i["title"] for i in items] == ["mine"]
    assert client.get("/api/v1/stats/dashboard", headers=auth("analyst_b")).json()["total_threats"] == 1


def test_geo_endpoint_does_not_leak_other_orgs_ioc_data(client, db, auth):
    _threat(db, ORG_A, source_ips=["203.0.113.9"])
    # org B knows where that IP is; org A has no IOC row for it
    db.table("iocs").insert({"organization_id": ORG_B, "ioc_type": "ipv4", "value": "203.0.113.9",
                             "normalized_value": "203.0.113.9", "geo_country": "RU"}).execute()
    assert client.get("/api/v1/threats/geo", headers=auth("analyst_a")).json()["total_threats"] == 0
    db.table("iocs").insert({"organization_id": ORG_A, "ioc_type": "ipv4", "value": "203.0.113.9",
                             "normalized_value": "203.0.113.9", "geo_country": "RU"}).execute()
    assert client.get("/api/v1/threats/geo", headers=auth("analyst_a")).json()["total_threats"] == 1


def test_soft_deleted_rows_are_hidden(client, db, auth):
    from datetime import datetime
    t = _threat(db, ORG_A, deleted_at=datetime.now(UTC).isoformat())
    assert client.get("/api/v1/threats", headers=auth("analyst_a")).json()["total"] == 0
    assert client.get(f"/api/v1/threats/{t['id']}", headers=auth("analyst_a")).status_code == 404


# ------------------------------------------------------------- API keys ----
def _mk_key(client, auth, scopes=("ingest",), who="admin_a"):
    r = client.post("/api/v1/api-keys", json={"name": "collector", "scopes": list(scopes)}, headers=auth(who))
    assert r.status_code == 201, r.text
    return r.json()


def test_api_key_lifecycle_and_storage(client, db, auth):
    created = _mk_key(client, auth)
    raw = created["api_key"]
    assert raw.startswith("tbk_") and "api_key" not in client.get("/api/v1/api-keys", headers=auth("admin_a")).json()["items"][0]
    stored = db.rows("api_keys")[0]
    assert raw not in str(stored) and stored["key_hash"] != raw, "only a hash may be stored"

    ev = {"event": {"title": "benign", "event_type": "x"}}
    assert client.post("/api/v1/ingest/event", json=ev, headers={"X-API-Key": raw}).status_code == 200

    assert client.delete(f"/api/v1/api-keys/{created['id']}", headers=auth("admin_a")).status_code == 204
    assert client.post("/api/v1/ingest/event", json=ev, headers={"X-API-Key": raw}).status_code == 401
    assert client.delete(f"/api/v1/api-keys/{created['id']}", headers=auth("admin_a")).status_code == 404
    actions = [a["action"] for a in db.rows("audit_logs")]
    assert "api_key.created" in actions and "api_key.revoked" in actions


def test_api_key_scope_is_enforced(client, auth):
    ingest_key = _mk_key(client, auth, ["ingest"])["api_key"]
    exec_key = _mk_key(client, auth, ["executor"])["api_key"]
    h_i, h_e = {"X-API-Key": ingest_key}, {"X-API-Key": exec_key}
    assert client.get("/api/v1/playbooks/approvals", headers=h_i).status_code == 403
    assert client.get("/api/v1/playbooks/approvals", headers=h_e).status_code == 200
    assert client.post("/api/v1/ingest/event", json={"event": {"title": "x"}}, headers=h_e).status_code == 403
    # keys can never reach general data endpoints or admin functions
    for h in (h_i, h_e):
        assert client.get("/api/v1/threats", headers=h).status_code == 403
        assert client.get("/api/v1/api-keys", headers=h).status_code == 403
        assert client.post("/api/v1/api-keys", json={"name": "x", "scopes": ["ingest"]}, headers=h).status_code == 403


def test_expired_and_garbage_api_keys(client, db, auth):
    created = _mk_key(client, auth)
    db.table("api_keys").update({"expires_at": "2020-01-01T00:00:00+00:00"}).eq("id", created["id"]).execute()
    assert client.get("/api/v1/playbooks/approvals", headers={"X-API-Key": created["api_key"]}).status_code == 401
    assert client.get("/api/v1/playbooks/approvals", headers={"X-API-Key": "tbk_" + "a" * 43}).status_code == 401
    assert client.get("/api/v1/playbooks/approvals", headers={"X-API-Key": "nonsense"}).status_code == 401


def test_api_key_org_is_fixed_by_the_key(client, auth, db):
    key = _mk_key(client, auth, ["ingest"], who="admin_a")["api_key"]
    client.post("/api/v1/ingest/event", json={"event": {"title": "Shadow", "event_type": "e", "command_line": "vssadmin delete shadows /all"}},
                headers={"X-API-Key": key})
    assert db.rows("threats", organization_id=ORG_A) and not db.rows("threats", organization_id=ORG_B)


def test_scope_validation_rejects_unknown_scopes(client, auth):
    r = client.post("/api/v1/api-keys", json={"name": "k", "scopes": ["admin"]}, headers=auth("admin_a"))
    assert r.status_code == 422
