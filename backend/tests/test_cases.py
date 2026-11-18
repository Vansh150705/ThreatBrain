"""Case management, approvals/executor workflow, metrics and report export."""

from __future__ import annotations

from tests.conftest import ORG_A
from tests.test_pipeline import _ingest


def _case(client, auth):
    out = _ingest(client, auth).json()
    return out["summary"]["incident_short_id"], out["summary"]["promoted_threat_short_id"]


# ----------------------------------------------------------- lifecycle ----
def test_incident_status_lifecycle_sets_timestamps_and_closes_threats(client, auth, db):
    inc, thr = _case(client, auth)
    h = auth("analyst_a")
    r = client.patch(f"/api/v1/incidents/{inc}", json={"status": "contained"}, headers=h)
    assert r.status_code == 200 and r.json()["contained_at"] and r.json()["resolved_at"] is None

    r = client.patch(f"/api/v1/incidents/{inc}", json={"status": "resolved"}, headers=h)
    assert r.json()["resolved_at"]
    assert db.rows("threats", short_id=thr)[0]["status"] == "resolved"
    assert client.get("/api/v1/stats/dashboard", headers=h).json()["open_incidents"] == 0

    r = client.patch(f"/api/v1/incidents/{inc}", json={"status": "investigating"}, headers=h)
    assert r.json()["resolved_at"] is None, "reopening clears the resolved stamp"

    changes = [a["changes"] for a in db.rows("audit_logs") if a["action"] == "incident.status_changed"]
    assert [c["status"]["to"] for c in changes] == ["contained", "resolved", "investigating"]


def test_false_positive_marks_threats_false_positive(client, auth, db):
    inc, thr = _case(client, auth)
    client.patch(f"/api/v1/incidents/{inc}", json={"status": "false_positive"}, headers=auth("analyst_a"))
    assert db.rows("threats", short_id=thr)[0]["status"] == "false_positive"


def test_viewer_cannot_change_cases(client, auth):
    inc, _ = _case(client, auth)
    assert client.patch(f"/api/v1/incidents/{inc}", json={"status": "closed"}, headers=auth("viewer_a")).status_code == 403
    assert client.post(f"/api/v1/incidents/{inc}/notes", json={"body": "hi"}, headers=auth("viewer_a")).status_code == 403
    assert client.get(f"/api/v1/incidents/{inc}/notes", headers=auth("viewer_a")).status_code == 200


def test_invalid_status_and_priority_rejected(client, auth):
    inc, _ = _case(client, auth)
    h = auth("analyst_a")
    assert client.patch(f"/api/v1/incidents/{inc}", json={"status": "banana"}, headers=h).status_code == 422
    assert client.patch(f"/api/v1/incidents/{inc}", json={"priority": "p9"}, headers=h).status_code == 422


def test_assignment_validates_membership(client, auth, db, users):
    inc, _ = _case(client, auth)
    h = auth("analyst_a")
    ok = client.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": users["admin_a"]}, headers=h)
    assert ok.status_code == 200 and ok.json()["assigned_to"] == users["admin_a"]
    # another tenant's user, a viewer, and a stranger are all refused
    for bad in (users["owner_b"], users["viewer_a"], "22222222-2222-2222-2222-222222222222"):
        r = client.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": bad}, headers=h)
        assert r.status_code == 400, bad
    # explicit null unassigns
    r = client.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": None}, headers=h)
    assert r.status_code == 200 and r.json()["assigned_to"] is None


def test_notes_and_timeline(client, auth):
    inc, thr = _case(client, auth)
    h = auth("analyst_a")
    assert client.post(f"/api/v1/incidents/{inc}/notes", json={"body": "   "}, headers=h).status_code == 400
    n = client.post(f"/api/v1/incidents/{inc}/notes", json={"body": "Called the asset owner."}, headers=h)
    assert n.status_code == 201 and n.json()["author_name"] == "Analyst A"
    notes = client.get(f"/api/v1/incidents/{inc}/notes", headers=h).json()
    assert notes["total"] == 1

    tl = client.get(f"/api/v1/incidents/{inc}/timeline", headers=h).json()["items"]
    kinds = {e["kind"] for e in tl}
    assert {"threat", "note", "audit"} <= kinds
    assert [e["ts"] for e in tl] == sorted(e["ts"] for e in tl)


def test_threat_triage_patch(client, auth, db):
    _, thr = _case(client, auth)
    r = client.patch(f"/api/v1/threats/{thr}", json={"status": "false_positive"}, headers=auth("analyst_a"))
    assert r.status_code == 200 and r.json()["status"] == "false_positive" and r.json()["resolved_at"]
    assert client.patch(f"/api/v1/threats/{thr}", json={"status": "bogus"}, headers=auth("analyst_a")).status_code == 422
    assert any(a["action"] == "threat.status_changed" for a in db.rows("audit_logs"))


def test_search_and_filters(client, auth, db):
    _case(client, auth)
    h = auth("analyst_a")
    assert client.get("/api/v1/threats?q=brute", headers=h).json()["total"] == 1
    assert client.get("/api/v1/threats?q=zzzz", headers=h).json()["total"] == 0
    assert client.get("/api/v1/threats?q=%25%27%2C()", headers=h).status_code == 200  # metacharacters are inert
    assert client.get("/api/v1/incidents?severity=critical", headers=h).json()["total"] == 0
    assert client.get("/api/v1/incidents?severity=high", headers=h).json()["total"] == 1


def test_report_export_includes_new_sections(client, auth):
    inc, _ = _case(client, auth)
    r = client.get(f"/api/v1/incidents/{inc}/report", headers=auth("analyst_a"))
    assert r.status_code == 200 and "Chain of custody" in r.text and "203.0.113.42" in r.text


# ------------------------------------------------------ approval queue ----
def _pending(db):
    return db.rows("playbook_approvals", organization_id=ORG_A)[0]


def test_approval_decision_flow_and_double_decision_conflict(client, auth, db):
    _case(client, auth)
    appr = _pending(db)
    url = f"/api/v1/playbooks/approvals/{appr['id']}/decision"
    assert client.post(url, json={"decision": "approved"}, headers=auth("analyst_a")).status_code == 403
    ok = client.post(url, json={"decision": "approved", "note": "confirmed"}, headers=auth("admin_a"))
    assert ok.status_code == 200 and ok.json()["status"] == "approved"
    again = client.post(url, json={"decision": "rejected"}, headers=auth("owner_a"))
    assert again.status_code == 409
    assert db.rows("playbook_approvals")[0]["status"] == "approved"
    assert any(a["action"] == "playbook.approved" for a in db.rows("audit_logs"))


def test_other_org_admin_cannot_decide(client, auth, db):
    _case(client, auth)
    appr = _pending(db)
    r = client.post(f"/api/v1/playbooks/approvals/{appr['id']}/decision", json={"decision": "approved"}, headers=auth("owner_b"))
    assert r.status_code == 404


def test_executor_end_to_end_with_scoped_key(client, auth, db):
    _case(client, auth)
    appr = _pending(db)
    key = client.post("/api/v1/api-keys", json={"name": "exec", "scopes": ["executor"]}, headers=auth("admin_a")).json()["api_key"]
    kh = {"X-API-Key": key}

    # nothing to do until a human approves
    assert client.get("/api/v1/playbooks/approvals?pending_execution=true", headers=kh).json()["total"] == 0
    # the executor cannot approve its own work
    assert client.post(f"/api/v1/playbooks/approvals/{appr['id']}/decision", json={"decision": "approved"}, headers=kh).status_code == 403
    # and cannot report on something that was never approved
    assert client.post(f"/api/v1/playbooks/approvals/{appr['id']}/execution", json={"result": "executed"}, headers=kh).status_code == 409

    client.post(f"/api/v1/playbooks/approvals/{appr['id']}/decision", json={"decision": "approved"}, headers=auth("admin_a"))
    queue = client.get("/api/v1/playbooks/approvals?pending_execution=true", headers=kh).json()
    assert [i["target"] for i in queue["items"]] == ["203.0.113.42"]

    done = client.post(f"/api/v1/playbooks/approvals/{appr['id']}/execution",
                       json={"result": "executed", "detail": "iptables DROP added"}, headers=kh)
    assert done.status_code == 200 and done.json()["execution_status"] == "executed"
    assert client.post(f"/api/v1/playbooks/approvals/{appr['id']}/execution", json={"result": "executed"}, headers=kh).status_code == 409
    audit = [a for a in db.rows("audit_logs") if a["action"].startswith("response.block_ip.")]
    assert audit and audit[-1]["actor_name"] == "tb-executor"
    assert client.get("/api/v1/playbooks/approvals?pending_execution=true", headers=kh).json()["total"] == 0


def test_executor_key_from_other_org_cannot_see_queue(client, auth, db):
    _case(client, auth)
    key = client.post("/api/v1/api-keys", json={"name": "exec-b", "scopes": ["executor"]}, headers=auth("owner_b")).json()["api_key"]
    assert client.get("/api/v1/playbooks/approvals", headers={"X-API-Key": key}).json()["total"] == 0


# -------------------------------------------------------------- metrics ----
def test_soc_metrics_reflect_pipeline_activity(client, auth, db):
    inc, _ = _case(client, auth)
    _ingest(client, auth)  # duplicate folded
    client.patch(f"/api/v1/incidents/{inc}", json={"status": "resolved"}, headers=auth("analyst_a"))
    m = client.get("/api/v1/stats/soc?days=7", headers=auth("analyst_a")).json()
    assert m["totals"]["threats"] == 1 and m["totals"]["raw_events_folded"] == 2
    assert m["totals"]["duplicates_suppressed"] == 1
    assert m["severity"]["high"] == 1 and sum(d["total"] for d in m["daily"]) == 1
    assert m["mttr"]["count"] == 1
    assert m["top_source_ips"][0] == {"ip": "203.0.113.42", "threats": 1}
    assert any(a["agent_key"] == "triage" for a in m["agents"])
    assert m["approvals"]["pending"] == 1
    # tenant scoped
    mb = client.get("/api/v1/stats/soc", headers=auth("analyst_b")).json()
    assert mb["totals"]["threats"] == 0 and mb["agents"] == []
    assert client.get("/api/v1/stats/soc?days=0", headers=auth("analyst_a")).status_code == 422
