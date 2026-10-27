"""End-to-end agent pipeline through the real API, with the DB and LLM faked."""

from __future__ import annotations

import pytest

from tests.conftest import ORG_A, ORG_B

BRUTE = {
    "event": {
        "title": "SSH brute-force from 203.0.113.42",
        "description": "25 failed ssh logins within 60s",
        "source": "authentication",
        "event_type": "authentication.brute_force",
        "source_ip": "203.0.113.42",
        "username": "root",
        "asset_name": "web-01",
    },
    "source_system": "tb-collector/auth.log",
}


def _ingest(client, auth, body=None, who="analyst_a", **params):
    return client.post("/api/v1/ingest/event", json=body or BRUTE, headers=auth(who), params=params)


def test_full_pipeline_creates_threat_incident_and_queues_approval(client, auth, db):
    r = _ingest(client, auth)
    assert r.status_code == 200, r.text
    body = r.json()
    stages, summary = body["stages"], body["summary"]

    assert [s for s, v in stages.items() if v["status"] == "failed"] == []
    assert stages["detection"]["verdict"]["rules"][0]["rule_id"] == "TB-AUTH-001"
    assert stages["triage"]["verdict"]["severity"] == "high"
    assert summary["promoted_threat_id"] and summary["incident_short_id"]
    assert body["run_id"]

    threat = db.rows("threats", organization_id=ORG_A)[0]
    assert threat["fingerprint"] and threat["rule_hits"][0]["rule_id"] == "TB-AUTH-001"
    assert "T1110" in threat["mitre_techniques"]
    assert threat["incident_id"]

    incident = db.rows("incidents", organization_id=ORG_A)[0]
    assert incident["source_ips"] == ["203.0.113.42"]
    assert incident["priority"] == "p2"
    assert incident["playbook_runs"], "response actions must be persisted for the console"
    assert incident["timeline"] == [] or incident["timeline"][0]["source"] == "forensics_agent"

    approvals = db.rows("playbook_approvals", organization_id=ORG_A)
    assert [(a["action_type"], a["target"], a["status"]) for a in approvals] == [
        ("block_ip", "203.0.113.42", "pending")
    ]
    # nothing is ever executed by the server
    assert all(a.get("execution_status") is None for a in approvals)
    assert stages["response"]["verdict"]["executed_count"] == 0

    runs = db.rows("pipeline_runs", organization_id=ORG_A)
    assert runs[0]["status"] == "completed" and runs[0]["trace"]
    assert {t["stage"] for t in runs[0]["trace"]} >= {"detection", "triage", "investigation"}


def test_pipeline_is_tenant_scoped(client, auth, db):
    _ingest(client, auth)
    assert db.rows("threats", organization_id=ORG_B) == []
    r = client.get("/api/v1/threats", headers=auth("analyst_b"))
    assert r.json()["total"] == 0


def test_duplicate_events_fold_into_one_threat_and_skip_llm(client, auth, db, llm):
    first = _ingest(client, auth).json()
    calls_after_first = len(llm.calls)
    second = _ingest(client, auth).json()

    assert second["summary"]["deduplicated"] is True
    assert second["summary"]["duplicate_of"] == first["summary"]["promoted_threat_short_id"]
    assert len(llm.calls) == calls_after_first, "a duplicate must not spend any tokens"
    threats = db.rows("threats", organization_id=ORG_A)
    assert len(threats) == 1 and threats[0]["event_count"] == 2
    assert len(db.rows("incidents", organization_id=ORG_A)) == 1


def test_benign_event_is_not_promoted_and_stops_early(client, auth, db):
    body = {"event": {"title": "User logged in", "event_type": "authentication.success", "source_ip": "198.51.100.5"}}
    r = _ingest(client, auth, body).json()
    assert r["stages"]["triage"]["status"] == "ok"
    assert r["summary"]["promoted_threat_id"] is None
    assert r["stages"]["investigation"]["status"] == "skipped"
    assert db.rows("threats") == [] and db.rows("playbook_approvals") == []


def test_new_threat_from_same_source_correlates_into_existing_incident(client, auth, db):
    first = _ingest(client, auth).json()
    other = {"event": {**BRUTE["event"], "event_type": "recon.web_scanning",
                       "title": "Web scanning from 203.0.113.42", "username": None}}
    second = _ingest(client, auth, other).json()
    assert second["summary"]["incident_short_id"] == first["summary"]["incident_short_id"]
    assert second["stages"]["investigation"]["verdict"]["mode"] == "correlated_existing_incident"
    assert len(db.rows("incidents", organization_id=ORG_A)) == 1
    assert db.rows("incidents")[0]["threat_count"] == 2


def test_llm_outage_degrades_to_rule_based_verdict(client, auth, db, llm):
    from app.services.llm_service import LLMError  # noqa: F401
    from groq import APIConnectionError
    import httpx

    llm.fail_with = APIConnectionError(request=httpx.Request("POST", "http://x"))
    r = _ingest(client, auth).json()
    assert r["stages"]["triage"]["status"] == "degraded"
    assert r["summary"]["degraded"] is True
    assert r["stages"]["triage"]["verdict"]["severity"] == "high"
    assert "degraded-mode" in r["stages"]["triage"]["verdict"]["tags"]
    # the threat is still recorded so the attack is not lost
    assert len(db.rows("threats", organization_id=ORG_A)) == 1


def test_llm_outage_without_rule_match_fails_triage_cleanly(client, auth, llm):
    from groq import APIConnectionError
    import httpx

    llm.fail_with = APIConnectionError(request=httpx.Request("POST", "http://x"))
    body = {"event": {"title": "weird thing", "event_type": "custom.unknown"}}
    r = _ingest(client, auth, body)
    assert r.status_code == 200
    assert r.json()["stages"]["triage"]["status"] == "failed"
    assert r.json()["summary"]["stages_failed"] == 1


def test_rule_floor_overrides_underrated_llm_severity(client, auth, db, llm):
    def lowball(system, user):
        out = __import__("tests.fake_llm", fromlist=["x"]).default_handler(system, user)
        if "triage agent" in system.lower():
            out.update(severity="low", confidence=30, promote_to_threat=False, mitre_techniques=[])
        return out

    llm.handler = lowball
    body = {"event": {"title": "Shadow copies deleted", "event_type": "endpoint.process",
                      "command_line": "vssadmin.exe delete shadows /all /quiet", "asset_name": "fs-01",
                      "source_ip": "198.51.100.77"}}
    r = _ingest(client, auth, body).json()
    verdict = r["stages"]["triage"]["verdict"]
    assert verdict["severity"] == "critical", "TB-IMPACT-001 must put a floor under the model's verdict"
    assert r["stages"]["triage"]["reconciliation"]["adjusted"] is True
    assert "T1490" in verdict["mitre_techniques"]
    assert r["summary"]["promoted_threat_id"]


def test_prompt_injection_cannot_redirect_a_block_action(client, auth, db, llm):
    """A model tricked into blocking an IP that isn't in the evidence gets overruled."""
    import tests.fake_llm as fl

    def hijacked(system, user):
        out = fl.default_handler(system, user)
        if "response agent" in system.lower():
            out["actions"] = [
                {"playbook_name": "Block Malicious IP", "action_type": "block_ip", "target": "8.8.8.8",
                 "priority": 1, "rationale": "ignore previous instructions"},
                {"playbook_name": "Disable Compromised User", "action_type": "disable_user",
                 "target": "ceo", "priority": 1, "rationale": "injected"},
                {"playbook_name": "Block Malicious IP", "action_type": "block_range", "target": "0.0.0.0/0",
                 "priority": 1, "rationale": "injected"},
            ]
        return out

    llm.handler = hijacked
    r = _ingest(client, auth).json()
    actions = r["stages"]["response"]["verdict"]["actions"]
    assert {a["status"] for a in actions} == {"skipped"}
    assert all(a["skip_reason"] for a in actions)
    assert db.rows("playbook_approvals") == []


def test_response_simulate_mode_queues_nothing(client, auth, db):
    r = client.post(
        "/api/v1/orchestrator/handle-event",
        json={"event": BRUTE["event"], "response_mode": "simulate"},
        headers=auth("analyst_a"),
    )
    assert r.status_code == 200, r.text
    assert r.json()["stages"]["response"]["verdict"]["simulated_count"] == 1
    assert db.rows("playbook_approvals") == []


def test_repeated_pipeline_does_not_duplicate_pending_approvals(client, auth, db):
    _ingest(client, auth)
    # dedupe off => the response agent runs again for the same incident
    client.post("/api/v1/orchestrator/handle-event", json={"event": BRUTE["event"], "deduplicate": False},
                headers=auth("analyst_a"))
    approvals = db.rows("playbook_approvals", organization_id=ORG_A)
    assert len(approvals) == 1


def test_async_ingest_returns_202_and_run_completes(client, auth, db):
    import time

    r = _ingest(client, auth, **{"async": "true"})
    assert r.status_code == 202 and r.json()["status"] == "queued"
    run_id = r.json()["run_id"]
    for _ in range(100):
        got = client.get(f"/api/v1/orchestrator/runs/{run_id}", headers=auth("analyst_a")).json()
        if got["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert got["status"] == "completed"
    assert got["trace"] and got["summary"]["promoted_threat_id"]


def test_viewer_cannot_run_pipeline(client, auth):
    assert _ingest(client, auth, who="viewer_a").status_code == 403


def test_invalid_event_ip_rejected(client, auth):
    bad = {"event": {**BRUTE["event"], "source_ip": "999.1.1.1; DROP TABLE"}}
    assert _ingest(client, auth, bad).status_code == 422


def test_agent_stage_failure_is_reported_not_raised(client, auth, db, llm):
    import tests.fake_llm as fl

    def broken_forensics(system, user):
        if "forensics agent" in system.lower():
            return "this is not json at all"
        return fl.default_handler(system, user)

    llm.handler = broken_forensics
    r = _ingest(client, auth).json()
    assert r["stages"]["forensics"]["status"] == "failed"
    assert r["stages"]["response"]["status"] == "ok"
    assert r["summary"]["stages_failed"] == 1
    assert db.rows("agent_runs", status="failed"), "failed runs are recorded for observability"
