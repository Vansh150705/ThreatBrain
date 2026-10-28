"""Tenant rule management: custom rules, versions, rollback, built-in overrides, test-before-enable."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.detection import attack_catalog
from app.detection.engine import Rule, RuleEngine, RuleError, get_engine, rule_from_dict, run_rule_tests
from app.services import detection_service
from app.services.supabase_client import get_supabase_admin

EDITABLE = ("name", "description", "severity", "confidence", "techniques", "tags", "match",
            "rule_references", "tuning_guidance", "tests")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _to_rule(definition: dict[str, Any]) -> Rule:
    d = {**definition, "id": definition.get("rule_key") or definition.get("id")}
    return rule_from_dict(d, source="custom")


def validate_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Validate a rule and run its inline tests. Never persists anything."""
    rule = _to_rule(definition)
    results = run_rule_tests(rule)
    expects = [r["expected"] for r in results]
    problems = attack_catalog.validate_ids(list(rule.techniques))
    return {
        "valid": True,
        "tactics": list(rule.tactics),
        "tests": results,
        "tests_passed": bool(results) and all(r["passed"] for r in results),
        "has_positive_and_negative": True in expects and False in expects,
        "attack_warnings": problems,
    }


def dry_run(definition: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    rule = _to_rule(definition)
    ev = {"title": "test event", "event_type": "generic.event", "raw_data": {}, **event}
    hits = RuleEngine([rule]).evaluate(ev)
    return {"matched": bool(hits), "matched_fields": hits[0].matched_fields if hits else []}


def list_rules(org_id: str) -> dict[str, Any]:
    client = get_supabase_admin()
    overrides = {r["rule_key"]: r for r in (client.table("rule_overrides").select("*").eq("organization_id", org_id).execute().data or [])}
    base = get_engine()
    builtin = []
    for r in base.rules:
        ov = overrides.get(r.id, {})
        builtin.append({
            "id": r.id, "name": r.name, "severity": r.severity, "confidence": r.confidence,
            "tactics": list(r.tactics), "techniques": list(r.techniques), "tags": list(r.tags),
            "tuning": r.tuning, "tests": len(r.tests),
            "enabled": ov.get("enabled", True), "severity_override": ov.get("severity_override"),
            "override_reason": ov.get("reason"),
        })
    custom = (
        client.table("detection_rules").select("*").eq("organization_id", org_id)
        .is_("deleted_at", "null").order("created_at", desc=True).execute().data or []
    )
    return {"version": base.version, "builtin": builtin, "custom": custom}


def coverage(org_id: str) -> dict[str, Any]:
    """ATT&CK coverage of the rules that are *actually enabled* for this tenant."""
    engine = detection_service.get_org_engine(org_id)
    by_tech: dict[str, list[str]] = {}
    for r in engine.rules:
        for t in r.techniques:
            by_tech.setdefault(t, []).append(r.id)
    tactics = []
    for tid, tname in attack_catalog.TACTICS.items():
        techs = [t for t, meta in attack_catalog.TECHNIQUES.items() if tid in meta["tactics"] and "." not in t]
        covered = [t for t in techs if t in by_tech or any(k.startswith(t + ".") for k in by_tech)]
        tactics.append({"id": tid, "name": tname, "techniques_in_catalog": len(techs), "covered": len(covered),
                        "uncovered": [t for t in techs if t not in covered]})
    return {"rule_version": engine.version, "techniques": by_tech, "tactics": tactics}


def create_rule(org_id: str, user_id: str | None, definition: dict[str, Any]) -> dict[str, Any]:
    rule = _to_rule(definition)
    if rule.id in {r.id for r in get_engine().rules}:
        raise RuleError(f"{rule.id} collides with a built-in rule id; choose another key")
    client = get_supabase_admin()
    existing = client.table("detection_rules").select("id").eq("organization_id", org_id).eq("rule_key", rule.id).is_("deleted_at", "null").execute().data
    if existing:
        raise RuleError(f"a rule with key {rule.id} already exists")
    row = {
        "organization_id": org_id, "rule_key": rule.id, "name": rule.name, "description": rule.description,
        "severity": rule.severity, "confidence": rule.confidence, "tactics": list(rule.tactics),
        "techniques": list(rule.techniques), "tags": list(rule.tags), "match": rule.match,
        "rule_references": list(rule.references), "tuning_guidance": rule.tuning, "tests": list(rule.tests),
        "status": "draft", "origin": definition.get("origin", "native"), "sigma_source": definition.get("sigma_source"),
        "version": 1, "created_by": user_id,
    }
    created = client.table("detection_rules").insert(row).execute().data[0]
    _snapshot(org_id, created, user_id, "created")
    return created


def _snapshot(org_id: str, row: dict[str, Any], user_id: str | None, note: str) -> None:
    body = {k: row.get(k) for k in (*EDITABLE, "rule_key", "tactics", "origin")}
    get_supabase_admin().table("detection_rule_versions").insert({
        "organization_id": org_id, "rule_id": row["id"], "version": row["version"],
        "definition": body, "change_note": note[:300], "changed_by": user_id,
    }).execute()


def _get(org_id: str, rule_id: str) -> dict[str, Any] | None:
    rows = (get_supabase_admin().table("detection_rules").select("*").eq("organization_id", org_id)
            .eq("id", rule_id).is_("deleted_at", "null").limit(1).execute().data)
    return rows[0] if rows else None


def update_rule(org_id: str, user_id: str | None, rule_id: str, changes: dict[str, Any], note: str = "") -> dict[str, Any] | None:
    cur = _get(org_id, rule_id)
    if cur is None:
        return None
    merged = {**cur, **{k: v for k, v in changes.items() if k in EDITABLE}}
    rule = _to_rule({**merged, "rule_key": cur["rule_key"]})
    patch = {
        "name": rule.name, "description": rule.description, "severity": rule.severity, "confidence": rule.confidence,
        "tactics": list(rule.tactics), "techniques": list(rule.techniques), "tags": list(rule.tags), "match": rule.match,
        "rule_references": list(rule.references), "tuning_guidance": rule.tuning, "tests": list(rule.tests),
        "version": cur["version"] + 1, "updated_at": _now(),
        # an edited rule must be re-validated before it fires again
        "status": "draft" if cur["status"] == "enabled" else cur["status"],
    }
    updated = (get_supabase_admin().table("detection_rules").update(patch).eq("organization_id", org_id).eq("id", rule_id).execute().data or [None])[0]
    if updated:
        _snapshot(org_id, updated, user_id, note or "edited")
        detection_service.invalidate(org_id)
    return updated


def set_status(org_id: str, rule_id: str, status: str) -> dict[str, Any] | None:
    cur = _get(org_id, rule_id)
    if cur is None:
        return None
    if status == "enabled":
        check = validate_definition({**cur, "rule_key": cur["rule_key"]})
        if not check["tests_passed"] or not check["has_positive_and_negative"]:
            raise RuleError("a rule can only be enabled when it has at least one positive and one negative test and all tests pass")
    out = (get_supabase_admin().table("detection_rules").update({"status": status, "updated_at": _now()})
           .eq("organization_id", org_id).eq("id", rule_id).execute().data or [None])[0]
    detection_service.invalidate(org_id)
    return out


def delete_rule(org_id: str, rule_id: str) -> dict[str, Any] | None:
    out = (get_supabase_admin().table("detection_rules").update({"deleted_at": _now(), "status": "disabled"})
           .eq("organization_id", org_id).eq("id", rule_id).is_("deleted_at", "null").execute().data or [None])[0]
    detection_service.invalidate(org_id)
    return out


def versions(org_id: str, rule_id: str) -> list[dict[str, Any]]:
    return (get_supabase_admin().table("detection_rule_versions").select("*").eq("organization_id", org_id)
            .eq("rule_id", rule_id).order("version", desc=True).execute().data or [])


def rollback(org_id: str, user_id: str | None, rule_id: str, version: int) -> dict[str, Any] | None:
    rows = (get_supabase_admin().table("detection_rule_versions").select("*").eq("organization_id", org_id)
            .eq("rule_id", rule_id).eq("version", version).limit(1).execute().data)
    if not rows:
        return None
    return update_rule(org_id, user_id, rule_id, rows[0]["definition"], note=f"rollback to v{version}")


def set_override(org_id: str, user_id: str | None, rule_key: str, *, enabled: bool, severity: str | None, reason: str | None) -> dict[str, Any]:
    if rule_key not in {r.id for r in get_engine().rules}:
        raise RuleError(f"{rule_key} is not a built-in rule")
    row = {"organization_id": org_id, "rule_key": rule_key, "enabled": enabled, "severity_override": severity,
           "reason": reason, "updated_by": user_id, "updated_at": _now()}
    out = get_supabase_admin().table("rule_overrides").upsert(row, on_conflict="organization_id,rule_key").execute().data[0]
    detection_service.invalidate(org_id)
    return out
