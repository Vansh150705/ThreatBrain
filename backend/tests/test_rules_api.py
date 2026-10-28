"""Custom rules, versioning, overrides, Sigma import and tenant isolation of detection content."""

from __future__ import annotations

from app.services import detection_service
from tests.conftest import ORG_A

RULE = {
    "rule_key": "corp-internal-tool",
    "name": "Forbidden internal tool",
    "severity": "high",
    "confidence": 80,
    "techniques": ["T1105"],
    "match": {"field": "command_line", "contains": "evil-tool"},
    "tests": [
        {"name": "hit", "event": {"command_line": "run evil-tool --go"}, "expect_match": True},
        {"name": "miss", "event": {"command_line": "run good-tool"}, "expect_match": False},
    ],
}
BASE = "/api/v1/rules"


def _create(client, auth, body=None, who="admin_a"):
    return client.post(BASE, json=body or RULE, headers=auth(who))


def test_custom_rule_lifecycle_draft_enable_fire(client, auth, db, drain):
    r = _create(client, auth)
    assert r.status_code == 201 and r.json()["status"] == "draft" and r.json()["tactics"] == ["TA0011"]
    rid = r.json()["id"]
    # a draft never fires
    detection_service.invalidate()
    assert not [h for h in detection_service.evaluate(ORG_A, {"command_line": "evil-tool", "raw_data": {}}) if h.rule_id == "corp-internal-tool"]
    en = client.post(f"{BASE}/{rid}/status", json={"status": "enabled"}, headers=auth("admin_a"))
    assert en.status_code == 200 and en.json()["status"] == "enabled"
    hits = detection_service.evaluate(ORG_A, {"command_line": "evil-tool", "raw_data": {}})
    assert [h.rule_id for h in hits if h.rule_id == "corp-internal-tool"]
    audit = [a["action"] for a in db.rows("audit_logs", organization_id=ORG_A)]
    assert "detection_rule.created" in audit and "detection_rule.enabled" in audit


def test_cannot_enable_rule_without_passing_positive_and_negative_tests(client, auth):
    body = {**RULE, "rule_key": "no-negative", "tests": [RULE["tests"][0]]}
    rid = _create(client, auth, body).json()["id"]
    r = client.post(f"{BASE}/{rid}/status", json={"status": "enabled"}, headers=auth("admin_a"))
    assert r.status_code == 422 and "negative" in r.json()["detail"]["message"]
    failing = {**RULE, "rule_key": "failing-test", "tests": [{"event": {"command_line": "nothing"}, "expect_match": True},
                                                            RULE["tests"][1]]}
    rid2 = _create(client, auth, failing).json()["id"]
    assert client.post(f"{BASE}/{rid2}/status", json={"status": "enabled"}, headers=auth("admin_a")).status_code == 422


def test_invalid_and_dangerous_rules_are_rejected(client, auth):
    for name, match in {
        "unbounded": {"field": "text", "regex": "a.*b"},
        "nested": {"field": "text", "regex": "(a+)+$"},
        "badop": {"field": "text", "frobnicate": "x"},
        "badcidr": {"field": "source_ip", "cidr": "not-a-cidr"},
    }.items():
        r = _create(client, auth, {**RULE, "rule_key": f"bad-{name}", "match": match})
        assert r.status_code == 422, name
    assert _create(client, auth, {**RULE, "rule_key": "bad-tech", "techniques": ["T9999999"]}).status_code == 422


def test_builtin_collision_and_duplicate_keys_rejected(client, auth):
    assert _create(client, auth, {**RULE, "rule_key": "TB-AUTH-001"}).status_code == 422
    assert _create(client, auth).status_code == 201
    assert _create(client, auth).status_code == 422


def test_editing_creates_version_returns_to_draft_and_rollback_restores(client, auth):
    rid = _create(client, auth).json()["id"]
    client.post(f"{BASE}/{rid}/status", json={"status": "enabled"}, headers=auth("admin_a"))
    up = client.put(f"{BASE}/{rid}", json={"severity": "low", "change_note": "too noisy"}, headers=auth("admin_a"))
    assert up.status_code == 200 and up.json()["version"] == 2 and up.json()["status"] == "draft" and up.json()["severity"] == "low"
    vs = client.get(f"{BASE}/{rid}/versions", headers=auth("analyst_a")).json()["items"]
    assert [v["version"] for v in vs] == [2, 1]
    rb = client.post(f"{BASE}/{rid}/rollback", json={"version": 1}, headers=auth("admin_a"))
    assert rb.status_code == 200 and rb.json()["severity"] == "high" and rb.json()["version"] == 3


def test_rbac_viewer_and_analyst_cannot_modify(client, auth):
    assert _create(client, auth, who="analyst_a").status_code == 403
    assert _create(client, auth, who="viewer_a").status_code == 403
    assert client.get(BASE, headers=auth("viewer_a")).status_code == 403  # rules are analyst+
    assert client.get(BASE, headers=auth("analyst_a")).status_code == 200


def test_tenants_cannot_see_or_modify_each_others_rules(client, auth):
    rid = _create(client, auth).json()["id"]
    assert client.put(f"{BASE}/{rid}", json={"severity": "low"}, headers=auth("admin_b")).status_code == 404
    assert client.post(f"{BASE}/{rid}/status", json={"status": "enabled"}, headers=auth("admin_b")).status_code == 404
    assert client.delete(f"{BASE}/{rid}", headers=auth("admin_b")).status_code == 404
    assert client.get(f"{BASE}/{rid}/versions", headers=auth("analyst_b")).json()["items"] == []
    assert client.get(BASE, headers=auth("analyst_b")).json()["custom"] == []
    # and a rule enabled in A does not fire in B
    client.post(f"{BASE}/{rid}/status", json={"status": "enabled"}, headers=auth("admin_a"))
    from tests.conftest import ORG_B
    detection_service.invalidate()
    assert not [h for h in detection_service.evaluate(ORG_B, {"command_line": "evil-tool", "raw_data": {}}) if h.rule_id == RULE["rule_key"]]


def test_builtin_override_disable_requires_reason_and_takes_effect(client, auth):
    from tests.conftest import ORG_A as A
    url = f"{BASE}/builtin/TB-DISC-001/override"
    assert client.put(url, json={"enabled": False}, headers=auth("admin_a")).status_code == 422
    assert client.put(f"{BASE}/builtin/NOPE-1/override", json={"enabled": False, "reason": "x"}, headers=auth("admin_a")).status_code == 404
    ev = {"command_line": 'net group "Domain Admins" /domain', "raw_data": {}}
    assert [h for h in detection_service.evaluate(A, ev) if h.rule_id == "TB-DISC-001"]
    assert client.put(url, json={"enabled": False, "reason": "AD admin tooling is normal here"}, headers=auth("admin_a")).status_code == 200
    assert not [h for h in detection_service.evaluate(A, ev) if h.rule_id == "TB-DISC-001"]
    sev = client.put(f"{BASE}/builtin/TB-AUTH-001/override", json={"enabled": True, "severity_override": "low"}, headers=auth("admin_a"))
    assert sev.status_code == 200
    hit = next(h for h in detection_service.evaluate(A, {"event_type": "authentication.brute_force", "raw_data": {}}) if h.rule_id == "TB-AUTH-001")
    assert hit.severity == "low"
    listed = client.get(BASE, headers=auth("analyst_a")).json()
    row = next(r for r in listed["builtin"] if r["id"] == "TB-DISC-001")
    assert row["enabled"] is False and row["override_reason"]


def test_sigma_import_creates_draft_with_warnings(client, auth):
    sig = "title: Evil tool usage\nlevel: high\ntags: [attack.t1105]\nlogsource: {product: linux}\ndetection:\n  s: {CommandLine|contains: evil-tool}\n  condition: s\n"
    r = client.post(f"{BASE}/sigma/import", json={"sigma": sig}, headers=auth("admin_a"))
    assert r.status_code == 201 and r.json()["rule"]["status"] == "draft" and r.json()["rule"]["origin"] == "sigma"
    assert r.json()["warnings"]
    bad = client.post(f"{BASE}/sigma/import", json={"sigma": "title: agg\ndetection:\n  s: {A: b}\n  condition: s | count() > 3\n"}, headers=auth("admin_a"))
    assert bad.status_code == 422


def test_dry_run_and_validate_do_not_persist(client, auth, db):
    r = client.post(f"{BASE}/dry-run", json={"rule": RULE, "event": {"command_line": "evil-tool"}}, headers=auth("analyst_a"))
    assert r.json()["matched"] is True
    v = client.post(f"{BASE}/validate", json=RULE, headers=auth("analyst_a")).json()
    assert v["tests_passed"] and v["has_positive_and_negative"]
    assert db.rows("detection_rules") == []


def test_coverage_reflects_enabled_rules(client, auth):
    cov = client.get(f"{BASE}/coverage", headers=auth("analyst_a")).json()
    assert "T1110" in cov["techniques"] or any(k.startswith("T1110") for k in cov["techniques"])
    ta = {t["id"]: t for t in cov["tactics"]}
    assert ta["TA0006"]["covered"] >= 1
    client.put(f"{BASE}/builtin/TB-AUTH-001/override", json={"enabled": False, "reason": "test"}, headers=auth("admin_a"))
    assert "TB-AUTH-001" not in client.get(f"{BASE}/coverage", headers=auth("analyst_a")).json()["techniques"].get("T1110.001", [])
