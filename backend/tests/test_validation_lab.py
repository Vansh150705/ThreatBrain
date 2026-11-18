"""The validation benchmark is a release gate: it must run and meet validation/gates.yaml."""

from __future__ import annotations

import json

import pytest
import yaml

from validation import runner, safety


@pytest.fixture(scope="module")
def engine_run():
    res = runner.run_engine()
    gates = yaml.safe_load((runner.ROOT / "gates.yaml").read_text())["gates"]
    return res, runner.summarize(res, gates)


def test_benchmark_meets_every_gate(engine_run):
    _, summary = engine_run
    failed = [k for k, ok in summary["gate_checks"].items() if not ok]
    assert not failed, f"gates failed: {failed}\n{json.dumps(summary['metrics'], indent=1)[:2000]}"


def test_corpus_has_the_advertised_breadth(engine_run):
    res, summary = engine_run
    m = summary["metrics"]
    assert m["attack_scenarios"] >= 150 and m["benign_scenarios"] >= 100
    assert len(res["chains"]) >= 12 and len(res["chains_negative"]) >= 5
    tactics = set(m["recall_by_tactic"])
    assert len(tactics) >= 12, tactics


def test_scenario_ids_are_unique():
    ids = []
    for f in ("attacks.yaml", "benign.yaml", "chains.yaml", "chains_negative.yaml", "evasion.yaml"):
        ids += [s["id"] for s in runner.load(f)]
    assert len(ids) == len(set(ids))


def test_known_gaps_are_documented_not_hidden(engine_run):
    res, summary = engine_run
    for e in res["evasion"]:
        if e.get("known_gap"):
            assert e["name"]
    for g in summary["metrics"]["accepted_gaps"]:
        assert g["reason"], f"{g['id']} is an accepted gap without a reason"
    # a gap that is now detected must be un-flagged rather than left to rot
    assert not summary["metrics"]["evasion_gaps_closed"], summary["metrics"]["evasion_gaps_closed"]


def test_report_is_machine_readable(engine_run, tmp_path):
    res, summary = engine_run
    report = {"schema": "threatbrain.validation/1", "summary": summary, "results": res}
    assert json.loads(json.dumps(report, default=str))["summary"]["metrics"]["recall"] <= 1.0


# ------------------------------------------------------------------ safety model
@pytest.mark.parametrize("url", ["http://127.0.0.1:8000", "http://localhost:8000/api", "https://[::1]:8443"])
def test_loopback_targets_allowed(url):
    safety.assert_lab_target(url, env={})


@pytest.mark.parametrize("url,env", [
    ("http://10.0.0.5:8000", {}),                                              # private but not authorised
    ("http://10.0.0.5:8000", {"LAB_AUTHORIZED": "1"}),                         # authorised but no allow-list
    ("http://10.0.0.5:8000", {"LAB_AUTHORIZED": "1", "LAB_ALLOWLIST": "192.168.0.0/16"}),  # not in allow-list
    ("http://8.8.8.8", {"LAB_AUTHORIZED": "1", "LAB_ALLOWLIST": "8.8.8.8"}),   # public address: always refused
    ("ftp://127.0.0.1", {}), ("not a url", {}), ("http://", {}),
])
def test_unsafe_targets_refused(url, env):
    with pytest.raises(safety.UnsafeTarget):
        safety.assert_lab_target(url, env=env)


def test_authorised_private_allowlisted_target_ok():
    safety.assert_lab_target("http://10.0.0.5:8000", env={"LAB_AUTHORIZED": "1", "LAB_ALLOWLIST": "10.0.0.0/24"})


def test_scenario_commands_are_never_executable():
    with pytest.raises(safety.UnsafeTarget):
        safety.assert_text_only("rm -rf /")


def test_no_subprocess_or_shell_in_the_lab():
    import pathlib
    import re
    for f in pathlib.Path(runner.ROOT).glob("*.py"):
        src = f.read_text()
        if f.name == "runner.py":
            src = src.replace('subprocess.check_output(["git", "rev-parse", "--short", "HEAD"]', "GIT")  # the one allowed call
        assert not re.search(r"os\.system|subprocess\.(run|Popen|call)|shell\s*=\s*True", src), f.name
