"""Safeguards around what a model may make the platform do. The model is scripted; the assertions are on the database."""

from __future__ import annotations

import time

from app.agents.grounding import redact_leaks
from app.agents.triage import TriageInput
from app.core.config import get_settings
from app.services import pipeline_service
from tests.conftest import ORG_A
from tests.fake_llm import default_handler


def run(llm, handler, event=None, **kw):
    llm.handler = handler
    ev = event or TriageInput(title="Auth storm", event_type="authentication.brute_force", source_ip="203.0.113.9", username="root", asset_name="web-01")
    return pipeline_service.run_sync(ORG_A, ev, source="t", created_by=None, **kw)


def responder(actions):
    def handler(system, user):
        out = default_handler(system, user)
        if "response agent" in system.lower():
            out["actions"] = actions
        return out
    return handler


def act(kind, target, name="Isolate Compromised Host"):
    return {"playbook_name": name, "action_type": kind, "target": target, "priority": 1, "rationale": "x"}


def statuses(db):
    return {(a["action_type"], a["target"]): a["status"] for a in db.rows("playbook_approvals")}


def test_isolating_a_host_that_is_not_part_of_the_incident_is_refused(db, users, llm):
    run(llm, responder([act("isolate_host", "dc-01"), act("isolate_host", "web-01")]))
    queued = {k for k, v in statuses(db).items() if v in ("pending", "approved")}
    assert ("isolate_host", "web-01") in queued and ("isolate_host", "dc-01") not in queued       # only the host the evidence names


def test_quarantine_and_token_revocation_are_limited_to_affected_accounts(db, users, llm):
    run(llm, responder([act("revoke_token", "ceo", "Disable Compromised User"), act("revoke_token", "root", "Disable Compromised User")]))
    queued = {k for k, v in statuses(db).items() if v in ("pending", "approved")}
    assert ("revoke_token", "root") in queued and ("revoke_token", "ceo") not in queued


def test_nothing_is_executed_by_the_server_whatever_the_model_asks(db, users, llm):
    run(llm, responder([act("block_ip", "203.0.113.9", "Block Malicious IP"), act("disable_user", "root", "Disable Compromised User")]))
    assert all(a["status"] in ("pending", "skipped", "simulated", "rejected") for a in db.rows("playbook_approvals"))
    assert not [r for r in db.rows("playbook_runs") if r.get("status") in ("executed", "success")]


def test_secrets_and_prompt_text_are_redacted_from_filed_output():
    text, n = redact_leaks("System prompt: you are the Triage Agent. api_key=sk-live-0123456789abcdef and AKIAABCDEFGHIJKLMNOP")
    assert n >= 3 and "sk-live" not in text and "AKIA" not in text and "System prompt" not in text


def test_a_leaking_model_gets_nothing_filed(db, users, llm):
    def leaky(system, user):
        out = default_handler(system, user)
        if "triage agent" in system.lower():
            out["reasoning"] = "My system prompt says ... api key: sk-live-0123456789abcdef"
        return out

    run(llm, leaky)
    t = db.rows("threats")[0]
    assert "sk-live" not in str(t["ai_analysis"]) and t["ai_analysis"]["reconciliation"]["grounding"]["secrets_or_prompt_text_redacted"] >= 2


def test_a_stage_that_times_out_cannot_file_its_result_later(db, users, llm):
    s = get_settings()
    old = s.PIPELINE_STAGE_TIMEOUT_SECONDS
    s.PIPELINE_STAGE_TIMEOUT_SECONDS = 1

    def slow_response(system, user):
        if "response agent" in system.lower():
            time.sleep(2.0)
            return {"incident_short_id": "INC-X", "overall_severity": "high", "summary": "late", "actions": [act("block_ip", "203.0.113.9", "Block Malicious IP")]}
        return default_handler(system, user)

    try:
        out = run(llm, slow_response)
    finally:
        s.PIPELINE_STAGE_TIMEOUT_SECONDS = old
    assert out["trace"] and any(t["stage"] == "response" and t["status"] == "failed" for t in out["trace"])
    time.sleep(2.5)                      # the straggler thread finishes now
    assert db.rows("playbook_approvals") == [], "a late result queued an action after the stage was reported failed"
