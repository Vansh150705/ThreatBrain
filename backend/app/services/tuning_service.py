"""Rule tuning from analyst feedback: gather evidence -> ask the agent -> VERIFY the proposal -> store a draft."""

from __future__ import annotations

from typing import Any

from app.agents import AgentInput, DetectionEngineeringAgent
from app.agents.detection_engineering.schemas import TuningOutput
from app.core.logging import get_logger
from app.detection.engine import RuleEngine, RuleError, get_engine, rule_from_dict, run_rule_tests
from app.services import event_processor, rule_service
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

MIN_FALSE_POSITIVES = 3
MAX_SAMPLES = 10
FP_STATUSES = {"false_positive"}
TP_STATUSES = {"resolved", "closed", "contained", "investigating", "confirmed"}


class NotEnoughFeedback(Exception):
    pass


class UnknownRule(Exception):
    pass


def _find_rule(org_id: str, rule_key: str) -> tuple[dict[str, Any], bool]:
    """(definition, is_builtin)"""
    for r in get_engine().rules:
        if r.id == rule_key:
            return ({"rule_key": r.id, "name": r.name, "severity": r.severity, "confidence": r.confidence,
                     "techniques": list(r.techniques), "tags": list(r.tags), "match": r.match,
                     "tuning_guidance": r.tuning, "tests": list(r.tests), "description": r.description}, True)
    rows = (get_supabase_admin().table("detection_rules").select("*").eq("organization_id", org_id)
            .eq("rule_key", rule_key).is_("deleted_at", "null").limit(1).execute().data)
    if not rows:
        raise UnknownRule(rule_key)
    return rows[0], False


def _event_dicts(org_id: str, threat_ids: list[str]) -> list[dict[str, Any]]:
    if not threat_ids:
        return []
    client = get_supabase_admin()
    links = client.table("threat_events").select("event_id, threat_id").eq("organization_id", org_id).in_("threat_id", threat_ids).execute().data or []
    ids = [link["event_id"] for link in links][: MAX_SAMPLES * 3]
    if not ids:
        return []
    rows = client.table("events").select("*").eq("organization_id", org_id).in_("id", ids).execute().data or []
    return [event_processor.event_to_input(r).model_dump(mode="json", exclude_none=True) for r in rows[:MAX_SAMPLES]]


def gather_evidence(org_id: str, rule_key: str) -> dict[str, Any]:
    threats = get_supabase_admin().table("threats").select("id, status, rule_hits").eq("organization_id", org_id).limit(2000).execute().data or []
    mine = [t for t in threats if any(isinstance(h, dict) and h.get("rule_id") == rule_key for h in (t.get("rule_hits") or []))]
    fp = [t for t in mine if t.get("status") in FP_STATUSES]
    tp = [t for t in mine if t.get("status") in TP_STATUSES]
    stats = {"threats_total": len(mine), "false_positive": len(fp), "confirmed_or_resolved": len(tp),
             "other": len(mine) - len(fp) - len(tp)}
    if len(fp) < MIN_FALSE_POSITIVES:
        raise NotEnoughFeedback(
            f"Only {len(fp)} threat(s) from this rule were closed as false positive; at least {MIN_FALSE_POSITIVES} are needed "
            "before a tuning proposal is meaningful.")
    return {"stats": stats, "fp_events": _event_dicts(org_id, [t["id"] for t in fp]),
            "tp_events": _event_dicts(org_id, [t["id"] for t in tp])}


def _view(ev: dict[str, Any]) -> dict[str, Any]:
    return {"title": "event", "event_type": "generic.event", "raw_data": {}, **ev}


def verify_proposal(definition: dict[str, Any], out: TuningOutput, fp: list[dict], tp: list[dict]) -> dict[str, Any]:
    """Machine verification of a model proposal. Returns the verdict plus every measurement."""
    reasons: list[str] = []
    current = rule_from_dict({**definition, "id": definition["rule_key"]}, source="builtin" if definition.get("_builtin") else "custom")
    cand_def = {**definition, "match": out.proposed_match, "tests": [t.model_dump() for t in out.tests],
                "rule_key": definition["rule_key"] + "-tuned"}
    try:
        cand = rule_from_dict({**cand_def, "id": cand_def["rule_key"]}, source="custom")
    except RuleError as exc:
        return {"accepted": False, "reasons": [f"proposed rule is invalid: {exc}"], "measurements": {}}
    tests = run_rule_tests(cand)
    exp = [t["expected"] for t in tests]
    if not tests or True not in exp or False not in exp:
        reasons.append("proposal must include at least one positive and one negative test")
    failed = [t["name"] for t in tests if not t["passed"]]
    if failed:
        reasons.append(f"proposal fails its own tests: {failed}")
    before, after = RuleEngine([current]), RuleEngine([cand])
    fp_before = sum(bool(before.evaluate(_view(e))) for e in fp)
    fp_after = sum(bool(after.evaluate(_view(e))) for e in fp)
    tp_before = sum(bool(before.evaluate(_view(e))) for e in tp)
    tp_after = sum(bool(after.evaluate(_view(e))) for e in tp)
    if fp and fp_after >= fp_before:
        reasons.append(f"does not reduce false positives ({fp_before} -> {fp_after} of {len(fp)} samples)")
    if tp_after < tp_before:
        reasons.append(f"loses genuine detections ({tp_before} -> {tp_after} of {len(tp)} samples)")
    return {"accepted": not reasons, "reasons": reasons, "candidate": cand_def,
            "measurements": {"false_positive_samples": len(fp), "fp_matched_before": fp_before, "fp_matched_after": fp_after,
                             "true_positive_samples": len(tp), "tp_matched_before": tp_before, "tp_matched_after": tp_after,
                             "own_tests": len(tests)}}


def propose(org_id: str, user_id: str | None, rule_key: str) -> dict[str, Any]:
    definition, builtin = _find_rule(org_id, rule_key)
    definition = {**definition, "_builtin": builtin}
    ev = gather_evidence(org_id, rule_key)
    payload = {"rule": {k: v for k, v in definition.items() if k in ("rule_key", "name", "severity", "match", "tuning_guidance", "techniques")},
               "stats": ev["stats"], "false_positive_samples": ev["fp_events"], "true_positive_samples": ev["tp_events"]}
    run = DetectionEngineeringAgent().run(AgentInput(organization_id=org_id, trigger_type="manual", payload=payload))
    out = TuningOutput.model_validate(run.output)
    result: dict[str, Any] = {"run_id": run.run_id, "evidence": ev["stats"], "recommendation": out.recommendation,
                              "assessment": out.assessment, "rationale": out.rationale, "changes": out.changes,
                              "stored_rule_id": None}
    if out.recommendation != "tune" or not out.proposed_match:
        result["verification"] = {"accepted": None, "reasons": ["no rule change proposed"], "measurements": {}}
        return result
    v = verify_proposal(definition, out, ev["fp_events"], ev["tp_events"])
    result["verification"] = {k: v[k] for k in ("accepted", "reasons", "measurements")}
    if v["accepted"]:
        cand = {**v["candidate"], "origin": "proposal", "name": f"{definition['name']} (tuned proposal)"[:200],
                "tuning_guidance": f"AI-proposed tuning from {ev['stats']['false_positive']} false positives. Review before enabling."}
        row = rule_service.create_rule(org_id, user_id, cand)
        result["stored_rule_id"] = row["id"]
    return result
