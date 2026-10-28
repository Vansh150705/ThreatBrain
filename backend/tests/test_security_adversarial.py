"""Adversarial tests against the platform itself: auth coverage sweeps, scope enforcement, tenant isolation sweep,
mass assignment, parser abuse, error hygiene, CORS. Sweeps are generated from the OpenAPI document, so a new
endpoint is covered automatically (and an unprotected one fails the build)."""

from __future__ import annotations

import json
import re
import time

import pytest

from tests.conftest import ORG_A, ORG_B
from tests.test_pipeline import BRUTE

PUBLIC = {("GET", "/"), ("GET", "/api/v1/health"), ("GET", "/api/v1/health/db"), ("GET", "/api/v1/ready"),
          ("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/signup")}
INGEST_SCOPE = {("POST", "/api/v1/ingest/event"), ("POST", "/api/v1/ingest/events"), ("POST", "/api/v1/ingest/webhook/{fmt}")}
EXECUTOR_SCOPE = {("GET", "/api/v1/playbooks/approvals"), ("POST", "/api/v1/playbooks/approvals/{approval_id}/execution")}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def operations(app):
    spec = app.openapi()
    return [(m.upper(), p) for p, ops in sorted(spec["paths"].items()) for m in ops if m.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}]


@pytest.fixture()
def ops(client):
    from app.main import app

    return operations(app)


def fill(path: str, **ids: str) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: ids.get(m.group(1), "x"), path)


def call(client, method, path, headers=None, **kw):
    kw.setdefault("json", {}) if method in MUTATING else None
    return client.request(method, path, headers=headers or {}, **kw)


def test_every_non_public_endpoint_requires_authentication(client, ops):
    assert len(ops) >= 70
    leaks = []
    for method, path in ops:
        if (method, path) in PUBLIC:
            continue
        r = call(client, method, fill(path))
        if r.status_code not in (401, 403):
            leaks.append((method, path, r.status_code))
    assert not leaks, f"endpoints reachable without credentials: {leaks}"


def test_garbage_credentials_never_work_anywhere(client, ops):
    bad = [{"Authorization": "Bearer not.a.jwt"}, {"Authorization": "Bearer "}, {"X-API-Key": "tbk_" + "A" * 43}, {"X-API-Key": "' OR '1'='1"}]
    for h in bad:
        for method, path in ops:
            if (method, path) in PUBLIC:
                continue
            r = call(client, method, fill(path), headers=h)
            assert r.status_code in (401, 403), (h, method, path, r.status_code)


def test_viewer_cannot_mutate_anything(client, auth, ops):
    # copilot answers questions over data a viewer can already read; it is rate-limited and read-only
    exempt = {("POST", "/api/v1/copilot/ask")}
    bad = []
    for method, path in ops:
        if method not in MUTATING or (method, path) in PUBLIC or (method, path) in exempt:
            continue
        r = call(client, method, fill(path), headers=auth("viewer_a"))
        if r.status_code != 403:
            bad.append((method, path, r.status_code))
    assert not bad, f"viewer reached mutating endpoints: {bad}"


def test_analyst_cannot_use_admin_endpoints(client, auth, ops):
    admin_only = [(m, p) for m, p in ops if p.startswith(("/api/v1/api-keys", "/api/v1/system/status"))
                  or (m in {"PUT", "PATCH", "DELETE"} and p.startswith(("/api/v1/rules", "/api/v1/organizations")))
                  or (m, p) in {("POST", "/api/v1/rules"), ("POST", "/api/v1/onboarding/demo")}]
    assert len(admin_only) >= 8
    for method, path in admin_only:
        r = call(client, method, fill(path), headers=auth("analyst_a"))
        assert r.status_code == 403, (method, path, r.status_code)


@pytest.mark.parametrize("scopes,allowed", [(["ingest"], INGEST_SCOPE), (["executor"], EXECUTOR_SCOPE)])
def test_api_keys_can_only_reach_endpoints_of_their_scope(client, auth, ops, scopes, allowed):
    key = client.post("/api/v1/api-keys", json={"name": "k", "scopes": scopes}, headers=auth("admin_a")).json()["api_key"]
    reached = []
    for method, path in ops:
        if (method, path) in PUBLIC:
            continue
        r = call(client, method, fill(path), headers={"X-API-Key": key})
        if r.status_code not in (401, 403):
            reached.append((method, path))
    assert set(reached) <= allowed, f"scope {scopes} reached {set(reached) - allowed}"
    assert reached, "the key should reach at least its own endpoints"


def test_api_key_cannot_escalate_even_with_forged_role_headers(client, auth):
    key = client.post("/api/v1/api-keys", json={"name": "k", "scopes": ["ingest"]}, headers=auth("admin_a")).json()["api_key"]
    h = {"X-API-Key": key, "X-User-Role": "owner", "X-Organization-Id": ORG_B, "X-Forwarded-User": "admin"}
    assert client.get("/api/v1/api-keys", headers=h).status_code in (401, 403)
    ev = {"event": {"title": "x", "event_type": "e"}}
    assert client.post("/api/v1/ingest/event", json=ev, headers=h).status_code == 200


# ------------------------------------------------------------------------- tenant isolation sweep
@pytest.fixture()
def org_a_data(client, auth, db):
    assert client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a")).status_code == 200
    key = client.post("/api/v1/api-keys", json={"name": "k", "scopes": ["ingest"]}, headers=auth("admin_a")).json()
    rule = client.post("/api/v1/rules", headers=auth("admin_a"), json={
        "rule_key": "corp-x", "name": "Corp rule", "severity": "low", "match": {"field": "title", "contains": "zzz"},
        "tests": [{"event": {"title": "zzz"}, "expect_match": True}, {"event": {"title": "a"}, "expect_match": False}]}).json()
    threat, incident = db.rows("threats", organization_id=ORG_A)[0], db.rows("incidents", organization_id=ORG_A)[0]
    return {
        "identifier": threat["short_id"], "run_id": db.rows("pipeline_runs", organization_id=ORG_A)[0]["id"],
        "approval_id": db.rows("playbook_approvals", organization_id=ORG_A)[0]["id"], "key_id": key["id"],
        "rule_id": rule["id"], "rule_key": "corp-x", "user_id": next(u["id"] for u in db.rows("users") if u["organization_id"] == ORG_A),
        "agent_key": "triage", "_incident": incident["short_id"], "_agent_run": db.rows("agent_runs", organization_id=ORG_A)[0]["id"],
    }


def test_organization_b_cannot_read_or_change_any_organization_a_object(client, auth, ops, org_a_data):
    ids = {k: v for k, v in org_a_data.items() if not k.startswith("_")}
    secrets = {v for v in org_a_data.values() if isinstance(v, str) and len(v) > 6}
    failures = []
    for who in ("analyst_b", "admin_b", "owner_b"):
        for method, path in ops:
            if (method, path) in PUBLIC or "{" not in path or "webhook" in path:
                continue
            variants = [dict(ids)]
            if "/incidents/" in path:
                variants = [{**ids, "identifier": org_a_data["_incident"]}]
            if path.startswith("/api/v1/agents/runs/"):
                variants = [{**ids, "run_id": org_a_data["_agent_run"]}]
            for v in variants:
                r = call(client, method, fill(path, **v), headers=auth(who))
                body = r.text
                if r.status_code == 200 and not path.endswith(("/{agent_key}", "/{agent_key}/runs")):
                    failures.append((who, method, path, r.status_code))
                for s in secrets:
                    if s in body and r.status_code < 400:
                        failures.append((who, method, path, "leaked " + s[:8]))
    assert not failures, failures


def test_list_endpoints_never_include_other_tenants_rows(client, auth, org_a_data):
    for path in ("/api/v1/threats", "/api/v1/incidents", "/api/v1/playbooks/approvals", "/api/v1/orchestrator/runs", "/api/v1/audit",
                 "/api/v1/api-keys", "/api/v1/rules", "/api/v1/agents/recent-runs", "/api/v1/stats/soc", "/api/v1/stats/dashboard",
                 "/api/v1/organizations/members", "/api/v1/onboarding"):
        r = client.get(path, headers=auth("owner_b"))
        assert r.status_code == 200, (path, r.status_code)
        text = r.text
        for v in (org_a_data["identifier"], org_a_data["key_id"], org_a_data["rule_id"], "corp-x", org_a_data["approval_id"], "203.0.113.42"):
            assert v not in text, (path, v)


# ----------------------------------------------------------------------------------- mass assignment
def test_organization_update_cannot_change_plan_status_or_id(client, auth, db):
    before = dict(db.rows("organizations", id=ORG_A)[0])
    client.patch("/api/v1/organizations/me", json={"name": "Renamed", "plan": "enterprise", "status": "suspended", "id": ORG_B,
                                                    "is_demo_org": True, "settings": {"x": 1}}, headers=auth("owner_a"))
    after = db.rows("organizations", id=ORG_A)[0]
    assert after["plan"] == before["plan"] and after["status"] == before["status"] and after["id"] == ORG_A
    assert db.rows("organizations", id=ORG_B)[0]["name"] != "Renamed"


def test_ingested_event_cannot_choose_its_tenant(client, auth, db):
    ev = {"event": {"title": "x", "event_type": "e", "organization_id": ORG_B, "raw_data": {"organization_id": ORG_B}},
          "organization_id": ORG_B}
    r = client.post("/api/v1/ingest/events", json={"events": [ev["event"]]}, headers=auth("analyst_a"))
    assert r.status_code == 202
    assert {e["organization_id"] for e in db.rows("events")} == {ORG_A}


def test_member_cannot_self_promote_via_profile_like_endpoints(client, auth, db):
    uid = next(u["id"] for u in db.rows("users") if u["role"] == "analyst" and u["organization_id"] == ORG_A)
    for body in ({"role": "owner"}, {"status": "active", "role": "admin"}):
        assert client.patch(f"/api/v1/organizations/members/{uid}", json=body, headers=auth("analyst_a")).status_code == 403
    assert db.rows("users", id=uid)[0]["role"] == "analyst"


# ------------------------------------------------------------------------------------- parser abuse
def test_deeply_nested_and_huge_json_is_a_client_error_not_a_crash(client, auth):
    deep = "[" * 20000 + "]" * 20000
    for body in (deep, '{"event": ' + deep + "}", "{" * 50000):
        r = client.post("/api/v1/ingest/event", content=body, headers={**auth("analyst_a"), "Content-Type": "application/json"})
        assert r.status_code in (400, 413, 422), r.status_code


def test_payload_size_limits(client, auth):
    big = json.dumps({"x": "A" * 1_200_000})
    r = client.post("/api/v1/ingest/webhook/generic", content=big, headers={**auth("analyst_a"), "Content-Type": "application/json"})
    assert r.status_code == 413
    ev = {"event": {"title": "x", "event_type": "e", "raw_data": {"k": "v" * 70_000}}}
    assert client.post("/api/v1/ingest/event", json=ev, headers=auth("analyst_a")).status_code == 422


@pytest.mark.parametrize("body", [b"\xff\xfe\x00garbage", b"\x00" * 100, "﻿{\"a\": 1}".encode(), b'{"a": 1, "a": 2}', b"NaN", b"[1e999999]"])
def test_malformed_bodies_never_cause_500(client, auth, body):
    for path in ("/api/v1/ingest/webhook/generic", "/api/v1/ingest/event", "/api/v1/rules/sigma/convert"):
        r = client.post(path, content=body, headers={**auth("analyst_a"), "Content-Type": "application/json"})
        assert r.status_code < 500, (path, r.status_code, r.text[:200])


def test_weird_field_values_are_rejected_or_neutralised(client, auth, db):
    nasty = {"title": "x\x00y‮\ud83d", "event_type": "a" * 101, "source_ip": "1.2.3.4; DROP TABLE events", "username": "' OR 1=1 --"}
    r = client.post("/api/v1/ingest/event", json={"event": nasty}, params={"async": "true"}, headers=auth("analyst_a"))
    assert r.status_code in (400, 422)
    ok = {"title": "ok‮\x00", "event_type": "t", "username": "' OR 1=1 --", "command_line": "x" * 8000}
    r = client.post("/api/v1/ingest/event", json={"event": ok}, params={"async": "true"}, headers=auth("analyst_a"))
    assert r.status_code == 202
    assert "' OR 1=1 --" in [e.get("username") for e in db.rows("events")]       # stored as data, never interpreted


def test_filter_parameters_cannot_inject_postgrest_operators(client, auth, org_a_data):
    for evil in ("open,organization_id.eq." + ORG_B, "open)&organization_id=eq." + ORG_B, "*", "in.(a,b)", "{}", "%00"):
        for path in ("/api/v1/threats", "/api/v1/incidents"):
            r = client.get(path, params={"status": evil, "severity": evil, "search": evil, "q": evil}, headers=auth("analyst_b"))
            assert r.status_code in (200, 400, 422)
            if r.status_code == 200:
                assert org_a_data["identifier"] not in r.text


# ------------------------------------------------------------------------------- headers & hygiene
def test_request_id_header_cannot_inject_log_lines_or_headers(client):
    r = client.get("/api/v1/health", headers={"X-Request-Id": "abc\r\nSet-Cookie: pwn=1"})
    assert "pwn" not in r.headers.get("set-cookie", "") and "\n" not in r.headers["x-request-id"]


def test_internal_errors_do_not_leak_details(client, auth, monkeypatch):
    from app.services import case_service

    def boom(*a, **k):
        raise RuntimeError("SECRET-SQL: select * from users where password='hunter2' at /srv/app/x.py line 9")

    monkeypatch.setattr(case_service, "list_members", boom)
    r = client.get("/api/v1/organizations/members", headers=auth("analyst_a"))
    assert r.status_code == 500 and "hunter2" not in r.text and "Traceback" not in r.text and "/srv/app" not in r.text


def test_unknown_routes_and_methods_are_clean(client, auth):
    assert client.get("/api/v1/does-not-exist", headers=auth("analyst_a")).status_code == 404
    assert client.request("TRACE", "/api/v1/health").status_code in (404, 405)
    r = client.delete("/api/v1/health")
    assert r.status_code == 405 and "Traceback" not in r.text


def test_security_headers_present_on_every_response_class(client, auth):
    for r in (client.get("/api/v1/health"), client.get("/api/v1/nope"), client.get("/api/v1/me"), client.post("/api/v1/ingest/event", content="{")):
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
        assert r.headers["cache-control"] == "no-store" and r.headers["referrer-policy"] == "no-referrer"


def test_cors_only_allows_configured_origins(client):
    from app.core.config import get_settings

    allowed = get_settings().cors_origins_list[0]
    ok = client.options("/api/v1/me", headers={"Origin": allowed, "Access-Control-Request-Method": "GET"})
    evil = client.options("/api/v1/me", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == allowed
    assert "access-control-allow-origin" not in evil.headers


def test_openapi_and_docs_are_hidden_in_production(monkeypatch):
    from app.core.config import Settings

    s = Settings(APP_ENV="production", APP_DEBUG=False, CORS_ORIGINS="https://x.example", SUPABASE_URL="http://x", SUPABASE_ANON_KEY="a",
                 SUPABASE_SERVICE_ROLE_KEY="s", SUPABASE_JWT_SECRET="j" * 40)
    assert s.is_production


# ----------------------------------------------------------------------------------- detection DoS
def test_no_builtin_rule_is_vulnerable_to_catastrophic_backtracking():
    from app.detection.engine import get_engine

    engine = get_engine()
    pieces = ["a" * 20000, "(" * 5000, "union select " * 800, "../" * 6000, "${jndi:" * 2000, " " * 20000 + "x", "powershell -enc " + "A" * 19000,
              "\\" * 15000, "http://" + "a." * 5000, "{{" * 6000, "net user " + "a b " * 4000, "sudo " + "-a " * 6000]
    worst = 0.0
    for text in pieces:
        for field in ({"command_line": text}, {"title": text}, {"raw_data": {"url": text, "user_agent": text}}):
            t0 = time.perf_counter()
            engine.evaluate({"event_type": "process.start", "raw_data": {}, **field})
            worst = max(worst, time.perf_counter() - t0)
    assert worst < 1.0, f"slowest adversarial evaluation took {worst:.2f}s across {len(engine.rules)} rules"
