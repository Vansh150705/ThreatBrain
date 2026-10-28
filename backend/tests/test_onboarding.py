from __future__ import annotations

from app.core.config import get_settings


def steps(client, auth, who="admin_a"):
    return {s["id"]: s["done"] for s in client.get("/api/v1/onboarding", headers=auth(who)).json()["steps"]}


def test_checklist_reflects_real_state(client, auth, db, drain):
    s = steps(client, auth)
    assert not s["api_key"] and not s["first_event"] and not s["first_threat"] and s["llm"]
    key = client.post("/api/v1/api-keys", json={"name": "c", "scopes": ["ingest"]}, headers=auth("admin_a")).json()
    assert steps(client, auth)["api_key"]
    body = {"event": {"title": "x", "event_type": "authentication.brute_force", "source_ip": "203.0.113.4"}}
    client.post("/api/v1/ingest/event", json=body, headers={"X-API-Key": key["api_key"]}, params={"async": "true"})
    drain()
    s = steps(client, auth)
    assert s["first_event"] and s["first_threat"]
    client.put("/api/v1/rules/builtin/TB-DISC-001/override", json={"enabled": False, "reason": "noisy"}, headers=auth("admin_a"))
    assert steps(client, auth)["rules"]


def test_checklist_is_per_tenant(client, auth, db, drain):
    client.post("/api/v1/api-keys", json={"name": "c", "scopes": ["ingest"]}, headers=auth("admin_a"))
    assert steps(client, auth, "owner_b")["api_key"] is False


def test_demo_campaign_runs_through_the_real_pipeline(client, auth, db, drain):
    r = client.post("/api/v1/onboarding/demo", headers=auth("admin_a"))
    assert r.status_code == 202 and r.json()["accepted"] == r.json()["total_events"] >= 10
    drain()
    ids = {d["rule_id"] for e in db.rows("events") for d in e["detections"]}
    assert {"TB-AUTH-002", "TB-WEB-002", "TB-EXEC-003", "TB-IMPACT-001", "TB-CLOUD-002"} <= ids        # real rule hits
    assert {"TB-COR-001", "TB-COR-003", "TB-COR-006", "TB-COR-009"} <= ids                           # real correlations
    benign = [e for e in db.rows("events") if e["title"] in ("Sign-in",)]
    assert benign and not any(e["alerted"] for e in benign)                                           # noise stays quiet
    assert db.rows("threats") and db.rows("incidents")
    assert client.get("/api/v1/onboarding", headers=auth("admin_a")).json()["demo_loaded"] is True
    # idempotent per timestamp-window? loading twice must not explode
    assert client.post("/api/v1/onboarding/demo", headers=auth("admin_a")).status_code == 202


def test_demo_requires_admin_and_can_be_disabled(client, auth, monkeypatch):
    assert client.post("/api/v1/onboarding/demo", headers=auth("analyst_a")).status_code == 403
    monkeypatch.setattr(get_settings(), "ALLOW_DEMO_LOAD", False)
    r = client.post("/api/v1/onboarding/demo", headers=auth("admin_a"))
    assert r.status_code == 403 and r.json()["detail"]["error"] == "demo_disabled"
