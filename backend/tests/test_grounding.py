"""LLM output is checked against the evidence before it is trusted, and conclusions record who decided what."""

from __future__ import annotations

import json

from app.agents.grounding import CONFIDENCE_CAP, entities, ground_triage
from app.agents.triage.schemas import TriageOutput
from app.schemas.common import SeverityLevel
from app.services.orchestrator_service import reconcile_verdict
from tests.conftest import ORG_A

EVENT = {"title": "Failed logon storm", "event_type": "authentication.failed", "source_ip": "203.0.113.9", "username": "root",
         "asset_name": "web-01", "command_line": None, "raw_data": {"path": "/var/log/auth.log"}}
DETECTION = {"matched": True, "severity_floor": "high", "confidence": 80, "tactics": [], "techniques": ["T1110"], "tags": [],
             "rules": [{"rule_id": "TB-AUTH-001", "name": "Brute force", "matched_fields": ["event_type"]}]}


def verdict(**kw) -> TriageOutput:
    base = dict(severity=SeverityLevel.HIGH, confidence=92, title="SSH brute force from 203.0.113.9", description="Many failures against root on web-01",
                reasoning="Repeated failed logons", mitre_techniques=["T1110"], mitre_tactics=["TA0006"],
                evidence=[{"source": "event", "detail": "203.0.113.9 failed 40 logons for root"}], promote_to_threat=True)
    base.update(kw)
    return TriageOutput(**base)


def test_entities_extracts_only_checkable_tokens():
    got = entities("Beacon to evil-c2.example and 198.51.100.7 dropped C:\\Users\\Public\\a.exe, see CVE-2021-44228 hash "
                   + "a" * 64 + " mail bob@corp.example /etc/shadow readme.txt and explorer.exe")
    assert {"evil-c2.example", "198.51.100.7", "cve-2021-44228", "c:/users/public/a.exe", "/etc/shadow"} <= got
    assert not {"readme.txt", "explorer.exe"} & got and "a" * 64 in got


def test_grounded_claims_keep_their_confidence_and_are_marked_verified():
    out, rec = ground_triage(verdict(), EVENT, DETECTION)
    assert out.confidence == 92 and not rec["confidence_capped"] and rec["evidence_unverified"] == 0
    assert out.evidence[0].verified is True


def test_invented_ip_in_evidence_is_flagged_and_confidence_capped():
    v = verdict(evidence=[{"source": "llm", "detail": "Also seen beaconing to 198.51.100.77"}, {"source": "event", "detail": "203.0.113.9 failed logons"}])
    out, rec = ground_triage(v, EVENT, DETECTION)
    assert [e.verified for e in out.evidence] == [False, True]
    assert rec["evidence_unverified"] == 1 and out.confidence == CONFIDENCE_CAP and rec["confidence_capped"]


def test_invented_cve_or_host_in_the_headline_is_recorded():
    out, rec = ground_triage(verdict(description="Exploitation of CVE-2023-99999 on db.corp.example"), EVENT, DETECTION)
    assert {"cve-2023-99999", "db.corp.example"} <= set(rec["unsupported_in_text"]) and out.confidence == CONFIDENCE_CAP


def test_facts_from_rules_and_context_count_as_evidence():
    ctx = {"threat_intel": {"summary": "198.51.100.77 is a known scanner"}}
    out, rec = ground_triage(verdict(evidence=[{"source": "threat_intel", "detail": "198.51.100.77 is a known scanner"}]), EVENT, DETECTION, ctx)
    assert out.evidence[0].verified is True and not rec["confidence_capped"]


def test_nonexistent_attack_ids_are_dropped_not_filed():
    out, rec = ground_triage(verdict(mitre_techniques=["T1110", "T9999", "T1110.999"], mitre_tactics=["TA0006", "TA9999"]), EVENT, DETECTION)
    assert out.mitre_techniques == ["T1110"] and out.mitre_tactics == ["TA0006"]
    assert rec["dropped_attack_techniques"] == ["T9999", "T1110.999"] and rec["dropped_attack_tactics"] == ["TA9999"]


def test_a_model_cannot_assert_that_its_own_evidence_is_verified():
    v = TriageOutput.model_validate({"severity": "high", "confidence": 90, "title": "t", "description": "d", "reasoning": "r",
                                     "evidence": [{"source": "llm", "detail": "from 198.51.100.77", "verified": True}]})
    assert v.evidence[0].verified is None


def test_provenance_separates_rules_from_the_model():
    low = verdict(severity=SeverityLevel.LOW, confidence=40, mitre_techniques=["T1059"], evidence=[{"source": "llm", "detail": "looks odd"}])
    out, rec = reconcile_verdict(low, DETECTION)
    p = rec["provenance"]
    assert out.severity.value == "high" and p["severity"] == "rules_floor_over_model" and p["model_severity"] == "low" and p["rule_severity_floor"] == "high"
    assert p["techniques"] == {"from_rules": ["T1110"], "from_model": ["T1059"]} and p["evidence"]["deterministic"] == 1 and p["evidence"]["model"] == 1
    degraded_out, drec = reconcile_verdict(low, DETECTION, degraded=True)
    assert drec["provenance"]["severity"] == "rules" and drec["provenance"]["model_used"] is False


def test_pipeline_files_the_provenance_and_flags_a_hallucinating_model(client, auth, db, drain, llm):
    from app.services import pipeline_service

    def liar(system: str, user: str):
        if "triage agent" in system.lower():
            return {"severity": "high", "confidence": 95, "title": "Brute force from 203.0.113.9 tied to APT41 infrastructure 198.51.100.200",
                    "description": "Same actor as CVE-2022-12345", "reasoning": "Matches known campaign",
                    "evidence": [{"source": "llm", "detail": "198.51.100.200 hosted the C2 in 2021"}], "mitre_techniques": ["T1110", "T0000"], "promote_to_threat": True}
        from tests.fake_llm import default_handler
        return default_handler(system, user)

    llm.handler = liar
    from app.agents.triage import TriageInput
    pipeline_service.run_sync(ORG_A, TriageInput(title="x", event_type="authentication.brute_force", source_ip="203.0.113.9", username="root", asset_name="web-01"),
                              source="t", created_by=None)
    threat = db.rows("threats")[0]
    ai = threat["ai_analysis"]["reconciliation"]
    assert ai["grounding"]["confidence_capped"] and "198.51.100.200" in ai["grounding"]["unsupported_in_text"] and ai["grounding"]["dropped_attack_techniques"] == ["T0000"]
    assert threat["confidence"] <= 70 and ai["provenance"]["evidence"]["model_unverified"] == 1
    assert json.dumps(threat["ai_analysis"]["evidence"])          # unverified evidence stays visible, flagged
    assert any(e.get("verified") is False for e in threat["ai_analysis"]["evidence"])
