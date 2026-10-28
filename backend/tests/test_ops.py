"""Readiness, system status, metrics exposition, config doctor, version tracking on agent runs."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime

from app.core.config import get_settings
from app.services import ops_service
from tests.conftest import ORG_A, ORG_B
from tests.test_pipeline import BRUTE


def test_ready_ok_when_db_and_schema_present(client, db):
    r = client.get("/api/v1/ready")
    assert r.status_code == 200 and r.json()["status"] == "ready"
    assert set(r.json()) == {"status", "warnings"}       # no internals for anonymous callers


def test_ready_503_when_database_fails(client, monkeypatch):
    monkeypatch.setattr(ops_service, "check_database", lambda: {"ok": False, "error": "ConnectionError"})
    r = client.get("/api/v1/ready")
    assert r.status_code == 503 and r.json()["status"] == "not_ready"


def test_ready_503_when_schema_is_missing(client, db, monkeypatch):
    monkeypatch.setattr(ops_service, "check_schema", lambda: {"ok": False, "missing_tables": ["jobs"], "ledger_has_required": None, "required": "x"})
    assert client.get("/api/v1/ready").status_code == 503


def test_dead_workers_warn_but_do_not_fail_readiness(client, db, monkeypatch):
    monkeypatch.setattr(get_settings(), "EMBEDDED_WORKER", False)
    out = ops_service.readiness()
    assert out["ready"] is True and any("no live queue workers" in w for w in out["warnings"])
    db.table("worker_heartbeats").insert({"worker_id": "w1", "role": "worker", "last_seen_at": datetime.now(UTC).isoformat()}).execute()
    out = ops_service.readiness()
    assert out["checks"]["workers"]["live"] == 1 and not any("no live queue workers" in w for w in out["warnings"])


def test_system_status_is_admin_only_and_has_no_secrets(client, auth):
    assert client.get("/api/v1/system/status", headers=auth("analyst_a")).status_code == 403
    r = client.get("/api/v1/system/status", headers=auth("admin_a"))
    assert r.status_code == 200
    body = r.json()
    assert body["detection"]["rules"] >= 100 and body["detection"]["correlations"] >= 12
    raw = json.dumps(body)
    s = get_settings()
    for secret in (s.SUPABASE_SERVICE_ROLE_KEY, s.SUPABASE_JWT_SECRET, s.GROQ_API_KEY):
        assert secret and secret not in raw


def test_metrics_disabled_without_token_and_protected_with_one(client, monkeypatch):
    assert client.get("/metrics").status_code == 404
    monkeypatch.setattr(get_settings(), "METRICS_TOKEN", "m" * 24)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer " + "m" * 24}).status_code == 200


def test_metrics_content(client, auth, db, drain, monkeypatch):
    monkeypatch.setattr(get_settings(), "METRICS_TOKEN", "m" * 24)
    client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"), params={"async": "true"})
    client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"), params={"async": "true"})   # duplicate
    drain()
    client.get("/api/v1/organizations/me", headers={"Authorization": "Bearer garbage"})
    text = client.get("/metrics", headers={"Authorization": "Bearer " + "m" * 24}).text
    assert 'tb_events_ingested_total{outcome="accepted"}' in text and 'tb_events_ingested_total{outcome="duplicate"}' in text
    assert 'tb_detection_hits_total{kind="rule",rule="TB-AUTH-001"}' in text
    assert 'tb_jobs_finished_total{kind="event.process",result="succeeded"}' in text
    assert 'tb_http_requests_total{method="POST",route="/api/v1/ingest/event",status="2xx"}' in text
    assert "tb_http_request_duration_seconds_bucket" in text and 'le="+Inf"' in text
    assert 'tb_queue_jobs{status="queued"}' in text and "tb_workers_live" in text
    assert "tb_auth_failures_total" in text
    assert "/api/v1/ingest/event/" not in text             # route template, not raw URLs (bounded cardinality)


def test_agent_runs_record_the_versions_that_produced_them(client, auth, db):
    client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"))
    runs = db.rows("agent_runs")
    assert runs
    v = runs[0]["input"]["versions"]
    assert v["app"] == get_settings().APP_VERSION and v["provider"] == "groq" and len(v["prompt_sha"]) == 12 and v["rules"]


def test_doctor_reports_actionable_failures(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "APP_SECRET", "")
    monkeypatch.setattr(get_settings(), "METRICS_TOKEN", "")
    res = {r["check"]: r for r in ops_service.doctor()}
    assert res["database"]["status"] == "ok" and res["schema"]["status"] == "ok"
    assert res["APP_SECRET"]["status"] == "warn" and "Set APP_SECRET" in res["APP_SECRET"]["fix"]
    assert res["detection content"]["status"] == "ok"


def test_doctor_cli_fails_loudly_on_bad_production_config():
    env = {"PATH": "/usr/bin:/bin", "APP_ENV": "production", "APP_DEBUG": "true", "CORS_ORIGINS": "*",
           "SUPABASE_URL": "http://x", "SUPABASE_ANON_KEY": "a", "SUPABASE_SERVICE_ROLE_KEY": "s",
           "SUPABASE_JWT_SECRET": "short", "PYTHONPATH": "."}
    p = subprocess.run([sys.executable, "-m", "app.doctor"], env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 1
    assert "APP_DEBUG must be false" in p.stdout and "CORS_ORIGINS must not contain" in p.stdout and "too short" in p.stdout


def test_dead_jobs_are_listed_and_requeueable_by_admins_only_without_payloads(client, auth, db):
    from app.services import queue_service

    job = queue_service.enqueue(ORG_A, "event.process", {"event_id": "secret-payload-marker"}, max_attempts=1)
    queue_service.claim("w1", 1)
    queue_service.fail({**job, "attempts": 1}, "w1", "boom", retryable=False)
    other = queue_service.enqueue(ORG_B, "event.process", {"event_id": "x"}, max_attempts=1)
    queue_service.claim("w2", 5)
    queue_service.fail({**other, "attempts": 1}, "w2", "boom", retryable=False)

    assert client.get("/api/v1/system/jobs", headers=auth("analyst_a")).status_code == 403
    r = client.get("/api/v1/system/jobs", headers=auth("admin_a"))
    assert r.status_code == 200 and [j["id"] for j in r.json()["items"]] == [job["id"]]
    assert "secret-payload-marker" not in r.text and "payload" not in r.json()["items"][0]
    assert client.post(f"/api/v1/system/jobs/{other['id']}/requeue", headers=auth("admin_a")).status_code == 404   # other tenant
    ok = client.post(f"/api/v1/system/jobs/{job['id']}/requeue", headers=auth("admin_a"))
    assert ok.status_code == 200 and ok.json()["status"] == "queued"
    assert client.post(f"/api/v1/system/jobs/{job['id']}/requeue", headers=auth("admin_a")).status_code == 404       # no longer dead
    assert client.get("/api/v1/system/jobs", params={"status": "bogus"}, headers=auth("admin_a")).status_code == 422
