"""Multi-split evaluation of ThreatBrain's detection, correlation and behavioural layers.

    python -m validation.evaluate --mode engine [--gate] [--pipeline-sample N]

Rules this report follows (they are the point of it):
  * Results are reported per split (development / tuning / heldout). They are never pooled into one percentage.
  * The held-out split is frozen (validation/freeze.py) and reported as AGGREGATES ONLY. Per-scenario detail goes to
    reports/heldout.detail.json, which no report links to and which must not be used to tune rules.
  * Gate thresholds come from validation/gates_v2.yaml and were fixed before the held-out sets were run.
  * Engine mode = real detection engine + correlation + behavioural engine. Pipeline mode (a sample) = the real FastAPI app,
    durable queue, worker, agents (scripted LLM), in-memory PostgREST stand-in.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent
sys.path.insert(0, str(BACKEND))

from validation import behavior_lab, corpus, mutations  # noqa: E402
from validation.runner import expand, pct  # noqa: E402

SEV = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
BASE = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - m) / d, 3), round((c + m) / d, 3)]


def rate(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "ci95": wilson(k, n)}


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=BACKEND, text=True).strip()
    except Exception:
        return "unknown"


# ------------------------------------------------------------------------------------------ detection primitives
def _norm(ev: dict[str, Any]) -> dict[str, Any]:
    from app.ingest.identity_event import canonicalize_event

    d = {k: v for k, v in ev.items() if k != "at"}
    d.setdefault("event_type", "generic.event")
    d.setdefault("raw_data", {})
    return canonicalize_event(d)


def detect_scenario(engine, sc: dict[str, Any]) -> tuple[list[Any], float]:
    hits, ms = [], 0.0
    for raw in sc["events"]:
        for ev in expand(raw):
            d = _norm(ev)
            t0 = time.perf_counter()
            hits += engine.evaluate(d)
            ms += (time.perf_counter() - t0) * 1000
    return hits, ms


def _family(t: str) -> str:
    return t.split(".")[0]


def _evidence_ok(engine_mod, sc: dict[str, Any], hits: list[Any]) -> bool:
    """Every matched field named by a hit must exist and be non-empty in the event that produced it."""
    from app.detection.engine import _lookup, build_view

    views = [build_view(_norm(e)) for raw in sc["events"] for e in expand(raw)]
    for h in hits:
        if not h.matched_fields:
            return False
        if not any(all(_lookup(v, f) not in (None, "", {}) for f in h.matched_fields) for v in views):
            return False
    return True


def attack_record(engine, sc: dict[str, Any], hl: set[str]) -> dict[str, Any]:
    hits, ms = detect_scenario(engine, sc)
    alerting = [h for h in hits if not h.signal]
    exp = {_family(t) for t in sc.get("techniques", [])}
    got = {_family(t) for h in hits for t in h.techniques}
    sev_got = max((SEV[h.severity] for h in hits), default=0)
    sev_exp = SEV.get(sc.get("severity", ""), 0)
    tactic = sc.get("tactic") or ""
    return {
        "id": sc["id"], "split": sc["split"], "tactic": tactic, "family": sc["family"], "techniques": sc.get("techniques", []),
        "high_signal": tactic in hl, "detected": bool(hits), "alerted": bool(alerting), "signal_only": bool(hits) and not alerting,
        "mapping_ok": bool(hits) and bool(exp & got),
        "rules": sorted({h.rule_id for h in hits}), "ms": ms,
        "severity_label": sc.get("severity"), "severity_got": next((k for k, v in SEV.items() if v == sev_got), None),
        "sev_delta": (sev_got - sev_exp) if (sev_exp and hits) else None,
        "evidence_ok": _evidence_ok(None, sc, hits) if hits else None,
    }


def benign_record(engine, sc: dict[str, Any]) -> dict[str, Any]:
    """A benign scenario is a false positive when it raises an ALERT. A signal (context such as an enumeration command) is recorded
    separately: it is stored and available to correlation but never creates a threat on its own."""
    hits, ms = detect_scenario(engine, sc)
    alerting = [h for h in hits if not h.signal]
    return {"id": sc["id"], "split": sc["split"], "family": sc["family"], "false_positive": bool(alerting), "signal_only": bool(hits) and not alerting,
            "any_hit": bool(hits), "rules": sorted({h.rule_id for h in alerting}), "ms": ms}


def chain_record(sc: dict[str, Any], events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    from app.detection.correlation import evaluate_all, rate_event_types
    from app.detection.engine import get_engine

    engine = get_engine()
    history: list[dict[str, Any]] = []
    fired: dict[str, list[str]] = {}
    first_alert_min: float | None = None
    evs = events if events is not None else sc["events"]
    ids = {f"{sc['id']}-{i}" for i in range(len(evs))}
    ev_ok = True
    for i, raw in enumerate(evs):
        for ev in expand(raw):
            d = _norm(ev)
            at = BASE + timedelta(minutes=raw.get("at", i))
            hits = engine.evaluate(d)
            if hits and first_alert_min is None:
                first_alert_min = raw.get("at", i)
            rec = {"id": f"{sc['id']}-{i}", "at": at, "detections": [h.rule_id for h in hits], "tactics": [h.tactics[0] for h in hits if h.tactics],
                   "techniques": [t for h in hits for t in h.techniques], "tags": [t for h in hits for t in h.tags],
                   "source_ip": d.get("source_ip"), "destination_ip": d.get("destination_ip"), "username": d.get("username"),
                   "asset_name": d.get("asset_name"), "event_type": d.get("event_type")}
            if hits or rec["event_type"] in rate_event_types():
                for h in evaluate_all(rec, history):
                    fired.setdefault(h.rule_id, []).extend(h.evidence)
                    if not (set(h.evidence) <= ids | {rec["id"]} and rec["id"] in h.evidence):
                        ev_ok = False
            history.append(rec)
    if "expect_correlation" in sc:
        passed = sc["expect_correlation"] in fired
        span = (max(e.get("at", i) for i, e in enumerate(evs)) - min(e.get("at", i) for i, e in enumerate(evs))) if evs else 0
        return {"id": sc["id"], "split": sc["split"], "kind": "positive", "expected": sc["expect_correlation"], "passed": passed,
                "fired": sorted(fired), "evidence_ok": ev_ok if passed else None, "detection_delay_min": span if passed else None,
                "first_alert_min": first_alert_min}
    return {"id": sc["id"], "split": sc["split"], "kind": "negative", "forbidden": sc["forbid_correlation"], "passed": sc["forbid_correlation"] not in fired, "fired": sorted(fired)}


# ------------------------------------------------------------------------------------------ aggregation
def agg_event_split(attacks: list[dict], benign: list[dict], reveal: bool, hl_only_gate: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {}
    tp = sum(a["detected"] for a in attacks)
    out["attacks"] = {"all": rate(tp, len(attacks)), "note": "'all' counts an attack as detected when ANY hit (alert or signal) names it"}
    hs = [a for a in attacks if a["high_signal"]]
    ls = [a for a in attacks if not a["high_signal"]]
    out["attacks"]["high_signal_tactics"] = rate(sum(a["detected"] for a in hs), len(hs))
    out["attacks"]["other_tactics"] = rate(sum(a["detected"] for a in ls), len(ls))
    by_t: dict[str, list[dict]] = {}
    by_f: dict[str, list[dict]] = {}
    for a in attacks:
        by_t.setdefault(a["tactic"] or "unmapped", []).append(a)
        by_f.setdefault(a["family"] or "other", []).append(a)
    out["recall_by_tactic"] = {k: rate(sum(x["detected"] for x in v), len(v)) for k, v in sorted(by_t.items())}
    out["recall_by_category"] = {k: rate(sum(x["detected"] for x in v), len(v)) for k, v in sorted(by_f.items())}
    det = [a for a in attacks if a["detected"]]
    out["mapping_accuracy"] = rate(sum(a["mapping_ok"] for a in det), len(det))
    techs = {t for a in attacks for t in a["techniques"]}
    dtechs = {t for a in attacks if a["detected"] for t in a["techniques"]}
    out["technique_coverage"] = {"techniques_tested": len(techs), "techniques_with_a_detected_scenario": len(dtechs)}
    lab = [a for a in det if a["sev_delta"] is not None]
    if lab:
        out["severity"] = {"labelled": len(lab), "exact": rate(sum(a["sev_delta"] == 0 for a in lab), len(lab)),
                           "within_one": rate(sum(abs(a["sev_delta"]) <= 1 for a in lab), len(lab)),
                           "underrated_2plus": rate(sum(a["sev_delta"] <= -2 for a in lab), len(lab)),
                           "overrated_2plus": rate(sum(a["sev_delta"] >= 2 for a in lab), len(lab))}
    ev = [a["evidence_ok"] for a in det if a["evidence_ok"] is not None]
    out["evidence_correct"] = rate(sum(ev), len(ev))
    fp = sum(b["false_positive"] for b in benign)
    out["benign"] = rate(fp, len(benign)) | {"note": "rate = false-positive rate (alerts only)", "benign_with_any_hit_including_signals": sum(b.get("any_hit", b["false_positive"]) for b in benign)}
    out["attacks"]["alerted_not_just_signalled"] = rate(sum(a["alerted"] for a in attacks), len(attacks))
    atp = sum(a["alerted"] for a in attacks)
    out["precision"] = round(atp / (atp + fp), 4) if atp + fp else None
    ms = [a["ms"] for a in attacks + benign if "ms" in a]
    out["engine_ms_per_scenario"] = {"p50": round(pct(ms, 50), 3), "p95": round(pct(ms, 95), 3)} if ms else None
    if reveal:
        out["missed"] = [{"id": a["id"], "tactic": a["tactic"], "techniques": a["techniques"]} for a in attacks if not a["detected"]][:60]
        out["false_positives"] = [{"id": b["id"], "rules": b["rules"]} for b in benign if b["false_positive"]]
        out["wrong_mapping"] = [a["id"] for a in det if not a["mapping_ok"]][:40]
    return out


def agg_chains(chains: list[dict], reveal: bool) -> dict[str, Any]:
    pos = [c for c in chains if c["kind"] == "positive"]
    neg = [c for c in chains if c["kind"] == "negative"]
    ev = [c["evidence_ok"] for c in pos if c.get("evidence_ok") is not None]
    delays = [c["detection_delay_min"] for c in pos if c.get("detection_delay_min") is not None]
    first = [c["first_alert_min"] for c in pos if c.get("first_alert_min") is not None]
    out = {"campaigns": rate(sum(c["passed"] for c in pos), len(pos)), "near_misses_stay_quiet": rate(sum(c["passed"] for c in neg), len(neg)),
           "evidence_correct": rate(sum(ev), len(ev)),
           "minutes_from_first_to_last_stage_median": statistics.median(delays) if delays else None,
           "minutes_to_first_alert_median": statistics.median(first) if first else None}
    if reveal:
        out["failed"] = [{"id": c["id"], "expected": c.get("expected") or c.get("forbidden"), "fired": c["fired"]} for c in chains if not c["passed"]]
    return out


# ------------------------------------------------------------------------------------------ behavioural split
def eval_behavior(items: list[dict[str, Any]], mode: str) -> list[dict[str, Any]]:
    out = []
    for sc in items:
        res = behavior_lab.run_engine_scenario(sc) if mode == "engine" else behavior_lab.run_service_scenario(sc)
        out.append({**behavior_lab.judge({"id": sc["id"], "name": sc["name"], "label": sc["label"], "known_gap": sc.get("known_gap"), "gap_reason": sc.get("gap_reason")}, res), "split": sc["split"]})
    return out


def agg_behavior(rows: list[dict], reveal: bool) -> dict[str, Any]:
    atk = [r for r in rows if r["label"] == "attack" and not r.get("known_gap")]
    gaps = [r for r in rows if r.get("known_gap")]
    ben = [r for r in rows if r["label"] == "benign"]
    out = {"attacks_detected": rate(sum(r["alerted"] for r in atk), len(atk)), "benign_alerted": rate(sum(r["alerted"] for r in ben), len(ben)),
           "documented_cold_start_gaps": len(gaps), "median_hours_to_first_alert": statistics.median([r["first_alert_after_h"] for r in atk if r["first_alert_after_h"] is not None] or [0])}
    if reveal:
        out["failed"] = [{"id": r["id"], "label": r["label"]} for r in rows if not r["passed"] and not r.get("known_gap")]
    return out


# ------------------------------------------------------------------------------------------ metamorphic
def metamorphic(engine, scenarios: list[dict[str, Any]], seed: int = 7) -> dict[str, Any]:
    rnd = random.Random(seed)
    attacks = [s for s in scenarios if s["role"] == "attack" and s["kind"] in ("event", "adversarial")]
    benign = [s for s in scenarios if s["role"] == "benign"]
    per: dict[str, dict[str, int]] = {}
    base_detected = []
    for sc in attacks:
        hits, _ = detect_scenario(engine, sc)
        if hits:
            base_detected.append((sc, hits))
    for name in mutations.ALL:
        row = per.setdefault(name, {"applicable": 0, "retained": 0, "same_technique": 0})
        for sc, hits in base_detected:
            if len(sc["events"]) != 1 or "adapter" in sc["events"][0]:
                continue
            mev = mutations.mutate_event(sc["events"][0], name, rnd)
            if mev is None:
                continue
            row["applicable"] += 1
            mh, _ = detect_scenario(engine, {**sc, "events": [mev]})
            row["retained"] += bool(mh)
            row["same_technique"] += bool({_family(t) for h in mh for t in h.techniques} & {_family(t) for h in hits for t in h.techniques})
    ben_total = ben_fp = 0
    wrap_total = wrap_fp = 0
    for sc in benign:
        if len(sc["events"]) != 1 or "adapter" in sc["events"][0]:
            continue
        for name in mutations.ALL:
            mev = mutations.mutate_event(sc["events"][0], name, rnd)
            if mev is None:
                continue
            fired = any(not h.signal for h in detect_scenario(engine, {**sc, "events": [mev]})[0])
            if name in mutations.WRAPPERS:
                wrap_total += 1
                wrap_fp += fired      # base64-wrapping a command is itself the suspicious act, so an alert is correct here
            else:
                ben_total += 1
                ben_fp += fired
    app = sum(r["applicable"] for r in per.values())
    ret = sum(r["retained"] for r in per.values())
    return {"base_scenarios_detected": len(base_detected), "variants": app, "retention": rate(ret, app),
            "retention_same_technique": rate(sum(r["same_technique"] for r in per.values()), app),
            "by_mutation": {k: {"applicable": v["applicable"], "retention": rate(v["retained"], v["applicable"])["rate"],
                                "same_technique": rate(v["same_technique"], v["applicable"])["rate"]} for k, v in per.items() if v["applicable"]},
            "benign_mutations": rate(ben_fp, ben_total) | {"note": "rate = alerts on benign events after cosmetic mutations (case, spacing, quoting, paths, concatenation)"},
            "benign_wrapped_in_encoding": rate(wrap_fp, wrap_total) | {"note": "EXPECTED to alert: a benign command re-sent as -EncodedCommand or base64|sh is the evasion pattern itself"}}


# ------------------------------------------------------------------------------------------ degraded telemetry
def degraded(engine, scenarios: list[dict[str, Any]], seed: int = 3) -> dict[str, Any]:
    rnd = random.Random(seed)
    chains = [s for s in scenarios if s["role"] == "chain"]
    single = [s for s in scenarios if s["role"] == "attack" and s["kind"] in ("event", "adversarial") and len(s["events"]) == 1 and "adapter" not in s["events"][0]]
    out: dict[str, Any] = {}
    base_ok = [c for c in chains if chain_record(c)["passed"]]
    out["chains_correlating_cleanly"] = len(base_ok)

    def retained(fn) -> dict[str, Any]:
        k = 0
        for c in base_ok:
            evs = fn([dict(e) for e in c["events"]])
            k += chain_record(c, evs)["passed"]
        return rate(k, len(base_ok))

    out["reordered_arrival"] = retained(lambda e: rnd.sample(e, len(e)))
    out["duplicated_events"] = retained(lambda e: [x for ev in e for x in (ev, dict(ev))])
    out["timestamps_jittered_within_window"] = retained(lambda e: [{**ev, "at": ev.get("at", 0) + rnd.randint(-2, 2)} for ev in e])
    out["clock_skew_all_events_plus_3h"] = retained(lambda e: [{**ev, "at": ev.get("at", 0) + 180} for ev in e])
    out["one_non_final_event_lost"] = retained(lambda e: e if len(e) < 3 else [x for i, x in enumerate(e) if i != rnd.randrange(len(e) - 1)])
    out["final_event_delayed_beyond_all_windows"] = {**retained(lambda e: [*e[:-1], {**e[-1], "at": e[-1].get("at", 0) + 100000}]), "note": "rate = still correlated; EXPECTED LOW: a correlation window is a limit by design"}
    out["identity_field_lost_on_one_stage"] = retained(lambda e: [{k: v for k, v in e[0].items() if k not in ("username", "asset_name")}, *e[1:]])

    def single_ret(fn) -> dict[str, Any]:
        base = [s for s in single if detect_scenario(engine, s)[0]]
        k = 0
        for s in base:
            k += bool(detect_scenario(engine, {**s, "events": [fn(dict(s["events"][0]))]})[0])
        return rate(k, len(base))

    out["command_line_truncated_to_120_chars"] = single_ret(lambda e: {**e, "command_line": (e.get("command_line") or "")[:120]} if e.get("command_line") else e)
    out["username_asset_and_process_name_missing"] = single_ret(lambda e: {k: v for k, v in e.items() if k not in ("username", "asset_name", "process_name")})
    out["event_type_unknown"] = single_ret(lambda e: {**e, "event_type": "generic.event"})
    out["raw_data_dropped_keeping_command_line"] = single_ret(lambda e: {**e, "raw_data": {}} if e.get("command_line") else e)
    return out


# ------------------------------------------------------------------------------------------ pipeline sample
def pipeline_sample(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Run scenarios through the real app + queue + worker + agents (scripted LLM) and measure what the platform does with them."""
    from fastapi.testclient import TestClient

    import tests.conftest as c
    from app.core.ratelimit import limiter
    from app.main import app
    from app.services import llm_service, queue_service, supabase_client
    from app.services.worker import Worker
    from tests.fake_llm import FakeGroq
    from tests.fake_supabase import FakeSupabase

    rows = []
    for sc in items:
        fake = FakeSupabase()
        supabase_client.get_supabase_admin.cache_clear()
        supabase_client.create_client = lambda *a, fake=fake, **k: fake  # type: ignore[assignment]
        users = c.seed(fake)
        llm = FakeGroq()
        llm_service._get_groq_client = lambda llm=llm: llm  # type: ignore[assignment]
        queue_service.reset_depth_cache()
        limiter.reset() if hasattr(limiter, "reset") else None
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {c.make_token(users['analyst_a'])}"}
        t0 = time.perf_counter()
        w = Worker(role="eval", concurrency=2)
        base = datetime.now(UTC) - timedelta(hours=1)
        detect_ms = None
        for i, raw in enumerate(sc["events"]):
            for ev in expand(raw):
                d = {k: v for k, v in ev.items() if k != "at"}
                d.setdefault("event_type", "generic.event")
                d.setdefault("raw_data", {})
                d["occurred_at"] = (base + timedelta(minutes=ev.get("at", i))).isoformat()
                r = client.post("/api/v1/ingest/event", json={"event": d, "source_system": f"eval/{sc['id']}"}, headers=headers, params={"async": "true"})
                assert r.status_code == 202, r.text
                for _ in range(20):
                    if not w.run_once(wait=True):
                        break
                if detect_ms is None and any(e.get("detections") for e in fake.rows("events")):
                    detect_ms = (time.perf_counter() - t0) * 1000
        w._pool.shutdown(wait=True)
        total_ms = (time.perf_counter() - t0) * 1000
        runs = fake.rows("pipeline_runs")
        rows.append({"id": sc["id"], "role": sc["role"], "alerted": any(e.get("alerted") for e in fake.rows("events")),
                     "ms_to_detection": detect_ms, "ms_to_investigation_complete": total_ms if runs else None,
                     "threats": len(fake.rows("threats")), "pipeline_runs": len(runs),
                     "runs_completed": sum(r["status"] == "completed" for r in runs), "runs_failed": sum(r["status"] == "failed" for r in runs),
                     "runs_degraded": sum(bool((r.get("summary") or {}).get("degraded")) for r in runs), "llm_calls": len(llm.calls)})
    atk = [r for r in rows if r["role"] == "attack"]
    ben = [r for r in rows if r["role"] == "benign"]
    pr = sum(r["pipeline_runs"] for r in rows)
    dts = [r["ms_to_detection"] for r in rows if r["ms_to_detection"] is not None]
    its = [r["ms_to_investigation_complete"] for r in rows if r["ms_to_investigation_complete"] is not None]
    return {"scenarios": len(rows), "attack_alerted": rate(sum(r["alerted"] for r in atk), len(atk)), "benign_alerted": rate(sum(r["alerted"] for r in ben), len(ben)),
            "pipeline_runs": pr, "runs_completed": sum(r["runs_completed"] for r in rows), "runs_failed": sum(r["runs_failed"] for r in rows),
            "runs_degraded": sum(r["runs_degraded"] for r in rows),
            "agent_execution_reliability": round(sum(r["runs_completed"] for r in rows) / pr, 4) if pr else None,
            "ms_ingest_to_detection": {"p50": round(pct(dts, 50), 1), "p95": round(pct(dts, 95), 1)} if dts else None,
            "ms_ingest_to_investigation_complete": {"p50": round(pct(its, 50), 1), "p95": round(pct(its, 95), 1)} if its else None,
            "llm": {"mode": "scripted", "calls": sum(r["llm_calls"] for r in rows), "tokens": None,
                    "note": "latency and tokens of a real model are NOT measured here; a live-provider mode does not exist yet, see docs/AGENT_EVALUATION.md"},
            "note": "wall time includes the in-memory database and a scripted model: it measures platform overhead, not production latency"}


# ------------------------------------------------------------------------------------------ orchestration
def run(mode: str, pipeline_n: int, quick: bool = False) -> dict[str, Any]:
    from app.detection.engine import get_engine

    reg = corpus.registry()
    hl = set(reg["high_signal_tactics"])
    engine = get_engine()
    items = corpus.load_corpus()
    result: dict[str, Any] = {"splits": {}}
    heldout_detail: dict[str, Any] = {}
    for split in ("development", "tuning", "heldout"):
        reveal = split != "heldout"
        sc_all = [s for s in items if s["split"] == split]
        atk = [attack_record(engine, s, hl) for s in sc_all if s["role"] == "attack"]
        ben = [benign_record(engine, s) for s in sc_all if s["role"] == "benign"]
        ch = [chain_record(s) for s in sc_all if s["role"] in ("chain", "chain_negative")]
        sec: dict[str, Any] = {"scenario_counts": {"attacks": len(atk), "benign": len(ben), "campaigns": len(ch)}}
        sources: dict[str, list] = {}
        for a in atk:
            sources.setdefault(a["id"].split("-")[0], []).append(a)
        # Hand-written, Atomic Red Team and adversarial-variant results are three different things: never pooled.
        art = [a for a in atk if a["id"].startswith("ART-")]
        lol = [a for a in atk if a["id"].startswith("LOL-")]
        adv_a = [a for a in atk if a["id"].startswith("ADV-")]
        adv_b = [b for b in ben if b["id"].startswith("ADV-")]
        hand = [a for a in atk if not a["id"].startswith(("ART-", "ADV-", "LOL-"))]
        hand_b = [b for b in ben if not b["id"].startswith("ADV-")]
        if hand or hand_b:
            sec["handwritten"] = agg_event_split(hand, hand_b, reveal)
        if art:
            sec["atomic_red_team"] = agg_event_split(art, [], reveal)
        if lol:
            sec["lolbas"] = agg_event_split(lol, [], reveal)
        if adv_a or adv_b:
            sec["adversarial_variants"] = agg_event_split(adv_a, adv_b, reveal)
        if ch:
            sec["campaigns"] = agg_chains(ch, reveal)
        beh_items = [s for s in sc_all if s["kind"] == "behavior"]
        if beh_items:
            beh = eval_behavior(beh_items, "engine")
            sec["behavior"] = agg_behavior(beh, reveal)
            if split == "development":
                sec["behavior"]["noise_simulation"] = behavior_lab.simulate_noise(seed=11)
            if split == "tuning":
                sec["behavior"]["noise_simulation"] = behavior_lab.simulate_noise(entities=200, days=50, seed=2027)     # consumed in round 3
            if split == "heldout":
                sec["behavior"]["noise_simulation"] = behavior_lab.simulate_noise(entities=260, days=55, seed=4242)
        result["splits"][split] = sec
        if not reveal:
            heldout_detail = {"attacks": atk, "benign": ben, "campaigns": ch}
    # evasion mutations and degraded telemetry (never pooled across splits)
    if not quick:
        dev_tune = [s for s in items if s["split"] in ("development", "tuning") and not s["id"].startswith("ART-")]
        art_tune = [s for s in items if s["split"] == "tuning" and s["id"].startswith("ART-")][:150]
        result["metamorphic"] = {"development_and_tuning": metamorphic(engine, dev_tune + art_tune),
                                 "heldout": metamorphic(engine, [s for s in items if s["split"] == "heldout" and not s["id"].startswith("ART-")])}
        result["degraded_telemetry"] = {"development_and_tuning": degraded(engine, dev_tune),
                                        "heldout_chains_and_attacks": degraded(engine, [s for s in items if s["split"] == "heldout" and not s["id"].startswith("ART-")])}
    if pipeline_n:
        rnd = random.Random(5)
        pool = [s for s in items if s["kind"] in ("event", "adversarial") and s["split"] in ("development", "tuning") and not s["id"].startswith("ART-") and s["role"] in ("attack", "benign")]
        result["pipeline_sample"] = pipeline_sample(rnd.sample(pool, min(pipeline_n, len(pool))))
    result["_heldout_detail"] = heldout_detail
    result["_rules"] = {"count": len(engine.rules), "version": engine.version}
    result["datasets_not_run"] = list(corpus.MISSING)
    return result


def check_gates(res: dict[str, Any], gates: dict[str, Any]) -> dict[str, Any]:
    g, out = gates["gates"], {}

    def chk(name: str, value: float | None, op: str, thr: float) -> None:
        ok = value is not None and (value >= thr if op == ">=" else value <= thr)
        out[name] = {"value": value, "threshold": thr, "op": op, "passed": bool(ok)}

    for split in ("development", "tuning", "heldout"):
        s, gs = res["splits"][split], g[split]
        ev = s["handwritten"]
        if split == "heldout":
            hw = s["handwritten"]
            chk("heldout.attack_recall", hw["attacks"]["all"]["rate"], ">=", gs["attack_recall_min"])
            chk("heldout.benign_fpr", hw["benign"]["rate"], "<=", gs["benign_fpr_max"])
            chk("heldout.mapping_accuracy", hw["mapping_accuracy"]["rate"], ">=", gs["mapping_accuracy_min"])
            sv = hw.get("severity")
            chk("heldout.severity_within_one", sv["within_one"]["rate"] if sv else None, ">=", gs["severity_within_one_min"])
            chk("heldout.severity_underrated", sv["underrated_2plus"]["rate"] if sv else None, "<=", gs["severity_underrated_max"])
            ca = s.get("campaigns", {})
            chk("heldout.campaigns", ca.get("campaigns", {}).get("rate"), ">=", gs["chain_pass_min"])
            chk("heldout.campaign_near_misses", ca.get("near_misses_stay_quiet", {}).get("rate"), ">=", gs["chain_negative_pass_min"])
            chk("heldout.art_high_signal_recall", s["atomic_red_team"]["attacks"]["high_signal_tactics"]["rate"], ">=", gs["art_high_signal_recall_min"])
            b = s["behavior"]
            chk("heldout.behavior_attack_recall", b["attacks_detected"]["rate"], ">=", gs["behavior_attack_recall_min"])
            chk("heldout.behavior_benign_fpr", b["benign_alerted"]["rate"], "<=", gs["behavior_benign_fpr_max"])
            chk("heldout.behavior_noise", b["noise_simulation"]["alerts_per_100_entity_days"], "<=", gs["behavior_noise_per_100_entity_days_max"])
        else:
            chk(f"{split}.attack_recall", ev["attacks"]["all"]["rate"], ">=", gs["attack_recall_min"])
            chk(f"{split}.benign_fpr", ev["benign"]["rate"], "<=", gs["benign_fpr_max"])
            if split == "development":
                chk("development.campaigns", s["campaigns"]["campaigns"]["rate"], ">=", gs["chain_pass_min"])
                b = s["behavior"]
                chk("development.behavior_attack_recall", b["attacks_detected"]["rate"], ">=", gs["behavior_attack_recall_min"])
                chk("development.behavior_benign_fpr", b["benign_alerted"]["rate"], "<=", gs["behavior_benign_fpr_max"])
            else:
                chk("tuning.art_high_signal_recall", s["atomic_red_team"]["attacks"]["high_signal_tactics"]["rate"], ">=", gs["art_high_signal_recall_min"])
                ad = s["adversarial_variants"]
                chk("tuning.adversarial_detect", ad["attacks"]["all"]["rate"], ">=", gs["adversarial_attack_detect_min"])
                chk("tuning.adversarial_benign_fpr", ad["benign"]["rate"], "<=", gs["adversarial_benign_fpr_max"])
                b = s["behavior"]
                chk("tuning.behavior_attack_recall", b["attacks_detected"]["rate"], ">=", g["development"]["behavior_attack_recall_min"])
                chk("tuning.behavior_benign_fpr", b["benign_alerted"]["rate"], "<=", g["heldout"]["behavior_benign_fpr_max"])
    if "metamorphic" in res:
        for name, m in res["metamorphic"].items():
            chk(f"metamorphic.{name}.retention", m["retention"]["rate"], ">=", g["metamorphic"]["retention_min"])
            chk(f"metamorphic.{name}.benign_mutation_fpr", m["benign_mutations"]["rate"], "<=", g["metamorphic"]["benign_mutation_fpr_max"])
        d = res["degraded_telemetry"]["development_and_tuning"]
        gd = g["degraded_telemetry"]
        chk("degraded.reordered_chains", d["reordered_arrival"]["rate"], ">=", gd["reorder_chain_retention_min"])
        chk("degraded.duplicated_chains", d["duplicated_events"]["rate"], ">=", gd["duplicate_chain_retention_min"])
        chk("degraded.truncated_commands", d["command_line_truncated_to_120_chars"]["rate"], ">=", gd["truncated_command_retention_min"])
        chk("degraded.field_loss", d["username_asset_and_process_name_missing"]["rate"], ">=", gd["field_loss_single_event_retention_min"])
    lat = res["splits"]["development"]["handwritten"].get("engine_ms_per_scenario")
    chk("performance.engine_ms_p95", lat["p95"] if lat else None, "<=", g["performance"]["engine_event_p95_ms_max"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["engine"], default="engine")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--pipeline-sample", type=int, default=0)
    ap.add_argument("--quick", action="store_true", help="skip metamorphic/degraded sections")
    ap.add_argument("--out", default=str(ROOT / "reports"))
    a = ap.parse_args()
    from validation import freeze

    problems = freeze.check()
    gates = yaml.safe_load((ROOT / "gates_v2.yaml").read_text())
    t0 = time.time()
    res = run(a.mode, a.pipeline_sample, a.quick)
    detail = res.pop("_heldout_detail")
    rules = res.pop("_rules")
    gate_res = check_gates(res, gates)
    failed = {k: v for k, v in gate_res.items() if not v["passed"]}
    report = {
        "schema": "threatbrain.evaluation/1",
        "environment": {"generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "git_sha": git_sha(), "python": platform.python_version(),
                        "rules": rules, "seconds": round(time.time() - t0, 1), "mode": a.mode},
        "freeze": {"intact": not problems, "problems": problems},
        "gates": gate_res, "failed_gates": sorted(failed), "passed": not failed and not problems, "results": res,
        "protocol": ("Held-out results are aggregates only. Per-scenario held-out detail is written to heldout.detail.json for the NEXT remediation "
                     "round and must not be consulted to tune rules against these same scenarios."),
    }
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(report, indent=1, default=str))
    (out / "heldout.detail.json").write_text(json.dumps(detail, indent=1, default=str))
    print(f"evaluation: {len(gate_res) - len(failed)}/{len(gate_res)} gates passed; freeze {'intact' if not problems else 'BROKEN'}")
    for k in sorted(failed):
        print(f"  FAILED {k}: {failed[k]['value']} (need {failed[k]['op']} {failed[k]['threshold']})")
    return 1 if a.gate and (failed or problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())
