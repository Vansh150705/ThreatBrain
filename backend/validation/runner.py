"""Run the validation corpus through ThreatBrain and write machine-readable + human reports.

Modes
  engine    detection engine + correlation only (no DB, no LLM). Fast; used for the precision/recall gates.
  pipeline  the real FastAPI app: HTTP ingest -> durable queue -> worker -> detection -> correlation ->
            agent pipeline -> threat/incident rows. The database is the in-memory PostgREST stand-in and the
            LLM is scripted, so LLM *quality* and live-database behaviour are NOT measured (reported as such).
"""

from __future__ import annotations

import argparse
import json
import platform
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

SCEN = ROOT / "scenarios"


def load(name: str) -> list[dict[str, Any]]:
    """attacks.yaml / benign.yaml also include the held-out file's attacks (HLD-*) / benign (HLB-*)."""
    items = yaml.safe_load((SCEN / name).read_text(encoding="utf-8"))["scenarios"]
    if name in ("attacks.yaml", "benign.yaml"):
        for extra_file, atk_prefix, ben_prefix in (("holdout.yaml", "HLD-", "HLB-"), ("holdout2.yaml", "HL2-", "HB2-")):
            extra = yaml.safe_load((SCEN / extra_file).read_text(encoding="utf-8"))["scenarios"]
            prefix = atk_prefix if name == "attacks.yaml" else ben_prefix
            items = items + [x for x in extra if x["id"].startswith(prefix)]
    return items


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round((p / 100) * (len(s) - 1))))]


def expand(ev: dict[str, Any]) -> list[dict[str, Any]]:
    """An event is either a ready normalised event or `{adapter, payload}` run through the real ingest adapter."""
    if "adapter" not in ev:
        return [ev]
    from app.ingest import parse_payload

    return [{**t.model_dump(mode="json", exclude_none=True), **({"at": ev["at"]} if "at" in ev else {})}
            for t in parse_payload(ev["adapter"], ev["payload"], max_events=50)]


def _event_dict(ev: dict[str, Any], at: datetime | None = None) -> dict[str, Any]:
    d = {k: v for k, v in ev.items() if k != "at"}
    d.setdefault("event_type", "generic.event")
    d.setdefault("raw_data", {})
    if at:
        d["occurred_at"] = at.isoformat()
    return d


# ---------------------------------------------------------------------------------- engine mode
def run_engine() -> dict[str, Any]:
    from app.detection.correlation import evaluate_all
    from app.detection.engine import get_engine

    engine = get_engine()
    base = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    latencies: list[float] = []

    def detect(ev: dict[str, Any]):
        hits_all = []
        for e in expand(ev):
            d = _event_dict(e)
            t0 = time.perf_counter()
            hits_all += engine.evaluate(d)
            latencies.append((time.perf_counter() - t0) * 1000)
        return hits_all

    out: dict[str, Any] = {"attacks": [], "benign": [], "chains": [], "chains_negative": [], "evasion": []}
    for sc in load("attacks.yaml"):
        hit_lists = [detect(e) for e in sc["events"]]
        hits = [h for hl in hit_lists for h in hl]
        out["attacks"].append(_attack_result(sc, hits))
    for sc in load("benign.yaml"):
        hits = [h for e in sc["events"] for h in detect(e)]
        out["benign"].append({"id": sc["id"], "name": sc["name"], "false_positive": bool(hits),
                              "rules": sorted({h.rule_id for h in hits})})
    for key, fname in (("chains", "chains.yaml"), ("chains_negative", "chains_negative.yaml")):
        for sc in load(fname):
            out[key].append(_chain_engine(sc, detect, base, evaluate_all))
    for sc in load("evasion.yaml"):
        hits = [h for e in sc["events"] for h in detect(e)]
        r = _attack_result(sc, hits)
        r["known_gap"] = bool(sc.get("known_gap"))
        out["evasion"].append(r)
    out["latency_ms"] = {"events": len(latencies), "p50": round(pct(latencies, 50), 3),
                         "p95": round(pct(latencies, 95), 3), "p99": round(pct(latencies, 99), 3),
                         "max": round(max(latencies), 3), "mean": round(statistics.mean(latencies), 3)}
    out["rule_count"] = len(engine.rules)
    out["rules_version"] = engine.version
    return out


def _family(t: str) -> str:
    return t.split(".")[0]


def _attack_result(sc: dict[str, Any], hits) -> dict[str, Any]:
    exp = {_family(t) for t in sc.get("techniques", [])}
    got = {_family(t) for h in hits for t in h.techniques}
    return {
        "id": sc["id"], "name": sc["name"], "tactic": sc.get("tactic"), "techniques": sc.get("techniques", []),
        "detected": bool(hits), "mapping_ok": bool(hits) and bool(exp & got),
        "rules": sorted({h.rule_id for h in hits}),
        **({"known_gap": True, "gap_reason": sc.get("gap_reason", "")} if sc.get("known_gap") else {}),
    }


def _chain_engine(sc, detect, base, evaluate_all) -> dict[str, Any]:
    from app.detection.correlation import rate_event_types

    history: list[dict[str, Any]] = []
    fired: list[str] = []
    for i, ev in enumerate(sc["events"]):
        at = base + timedelta(minutes=ev.get("at", i))
        hits = detect(ev)
        rec = {
            "id": f"{sc['id']}-{i}", "at": at.replace(tzinfo=None) if False else at,
            "detections": [h.rule_id for h in hits], "tactics": [t for h in hits for t in h.tactics],
            "techniques": [t for h in hits for t in h.techniques], "tags": [t for h in hits for t in h.tags],
            "source_ip": ev.get("source_ip"), "destination_ip": ev.get("destination_ip"),
            "username": ev.get("username"), "asset_name": ev.get("asset_name"),
        }
        rec["event_type"] = ev.get("event_type")
        if hits or rec["event_type"] in rate_event_types():
            fired += [h.rule_id for h in evaluate_all(rec, history)]
        history.append(rec)
    return _chain_verdict(sc, fired)


def _chain_verdict(sc: dict[str, Any], fired: list[str]) -> dict[str, Any]:
    if "expect_correlation" in sc:
        return {"id": sc["id"], "name": sc["name"], "expected": sc["expect_correlation"],
                "fired": sorted(set(fired)), "passed": sc["expect_correlation"] in fired}
    return {"id": sc["id"], "name": sc["name"], "forbidden": sc["forbid_correlation"],
            "fired": sorted(set(fired)), "passed": sc["forbid_correlation"] not in fired}


# -------------------------------------------------------------------------------- pipeline mode
def run_pipeline() -> dict[str, Any]:
    from fastapi.testclient import TestClient

    import tests.conftest as c  # sets env vars before app import
    from app.core.ratelimit import limiter
    from app.main import app
    from app.services import llm_service, queue_service, supabase_client
    from app.services.worker import Worker
    from tests.fake_llm import FakeGroq
    from tests.fake_supabase import FakeSupabase

    results: dict[str, Any] = {"attacks": [], "benign": [], "chains": [], "chains_negative": [], "evasion": []}
    e2e_ms: list[float] = []
    llm_calls = 0

    def fresh():
        fake = FakeSupabase()
        supabase_client.get_supabase_admin.cache_clear()
        supabase_client.create_client = lambda *a, **k: fake  # type: ignore[assignment]
        users = c.seed(fake)
        llm = FakeGroq()
        llm_service._get_groq_client = lambda: llm  # type: ignore[assignment]
        queue_service.reset_depth_cache()
        limiter.reset() if hasattr(limiter, "reset") else None
        return fake, users, llm

    def run_scenario(sc: dict[str, Any]) -> tuple[Any, list[dict[str, Any]], float]:
        nonlocal llm_calls
        fake, users, llm = fresh()
        client = TestClient(app)
        headers = {"Authorization": f"Bearer {c.make_token(users['analyst_a'])}"}
        base = datetime.now(UTC) - timedelta(hours=1)
        t0 = time.perf_counter()
        w = Worker(role="lab", concurrency=2)
        for i, raw_ev in enumerate(sc["events"]):
            for ev in expand(raw_ev):
                at = base + timedelta(minutes=ev.get("at", i))
                body = {"event": _event_dict(ev, at), "source_system": f"lab/{sc['id']}"}
                r = client.post("/api/v1/ingest/event", json=body, headers=headers, params={"async": "true"})
                assert r.status_code == 202, r.text
                for _ in range(20):
                    if not w.run_once(wait=True):
                        break
        w._pool.shutdown(wait=True)
        ms = (time.perf_counter() - t0) * 1000
        llm_calls += len(llm.calls)
        events = sorted(fake.rows("events"), key=lambda e: e["observed_at"])
        return fake, events, ms

    def hits_of(events: list[dict[str, Any]]):
        from types import SimpleNamespace as NS
        out = []
        for e in events:
            for d in e.get("detections") or []:
                out.append(NS(rule_id=d["rule_id"], techniques=d.get("techniques", []), kind=d.get("kind", "rule")))
        return out

    for sc in load("attacks.yaml"):
        _, events, ms = run_scenario(sc)
        e2e_ms.append(ms)
        results["attacks"].append(_attack_result(sc, [h for h in hits_of(events) if h.kind == "rule"]))
    for sc in load("benign.yaml"):
        _, events, ms = run_scenario(sc)
        e2e_ms.append(ms)
        hits = hits_of(events)
        results["benign"].append({"id": sc["id"], "name": sc["name"], "false_positive": bool(hits),
                                  "rules": sorted({h.rule_id for h in hits})})
    for key, fname in (("chains", "chains.yaml"), ("chains_negative", "chains_negative.yaml")):
        for sc in load(fname):
            _, events, ms = run_scenario(sc)
            e2e_ms.append(ms)
            fired = [h.rule_id for h in hits_of(events) if h.kind == "correlation"]
            results[key].append(_chain_verdict(sc, fired))
    for sc in load("evasion.yaml"):
        _, events, ms = run_scenario(sc)
        r = _attack_result(sc, [h for h in hits_of(events) if h.kind == "rule"])
        r["known_gap"] = bool(sc.get("known_gap"))
        results["evasion"].append(r)
    results["latency_ms"] = {"scenarios": len(e2e_ms), "p50": round(pct(e2e_ms, 50), 1), "p95": round(pct(e2e_ms, 95), 1),
                             "p99": round(pct(e2e_ms, 99), 1), "max": round(max(e2e_ms), 1),
                             "note": "ingest->detect->correlate->scripted-LLM pipeline->threat, in-process, in-memory DB"}
    results["llm"] = {"mode": "scripted", "calls": llm_calls, "tokens": None,
                      "note": "scripted responses: token usage and LLM verdict quality are NOT measured"}
    return results


# ------------------------------------------------------------------------------------ reporting
def summarize(res: dict[str, Any], gates: dict[str, float]) -> dict[str, Any]:
    accepted_gaps = [a for a in res["attacks"] if a.get("known_gap")]
    attacks = [a for a in res["attacks"] if not a.get("known_gap")]
    tp = sum(a["detected"] for a in attacks)
    fn = len(attacks) - tp
    benign = res["benign"]
    fp = sum(b["false_positive"] for b in benign)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / len(attacks) if attacks else 0.0
    fpr = fp / len(benign) if benign else 0.0
    detected = [a for a in attacks if a["detected"]]
    mapping = sum(a["mapping_ok"] for a in detected) / len(detected) if detected else 0.0
    chains, neg = res["chains"], res["chains_negative"]
    chain_recall = sum(c["passed"] for c in chains) / len(chains) if chains else 0.0
    chain_neg = sum(c["passed"] for c in neg) / len(neg) if neg else 1.0
    ev = res["evasion"]
    gap_closed = [e["id"] for e in ev if e.get("known_gap") and e["detected"]]
    unexpected_miss = [e["id"] for e in ev if not e.get("known_gap") and not e["detected"]]
    by_tactic: dict[str, dict[str, int]] = {}
    for a in attacks:
        t = by_tactic.setdefault(a["tactic"] or "?", {"scenarios": 0, "detected": 0})
        t["scenarios"] += 1
        t["detected"] += int(a["detected"])
    metrics = {
        "attack_scenarios": len(attacks), "true_positives": tp, "false_negatives": fn,
        "accepted_gaps": [{"id": a["id"], "name": a["name"], "reason": a.get("gap_reason", ""), "now_detected": a["detected"]} for a in accepted_gaps],
        "benign_scenarios": len(benign), "false_positives": fp,
        "recall": round(recall, 4), "precision": round(precision, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "false_positive_rate": round(fpr, 4), "mapping_accuracy": round(mapping, 4),
        "chain_recall": round(chain_recall, 4), "chain_negative_pass": round(chain_neg, 4),
        "evasion_probes": len(ev), "evasion_detected": sum(e["detected"] for e in ev),
        "evasion_known_gaps_open": sum(1 for e in ev if e.get("known_gap") and not e["detected"]),
        "evasion_gaps_closed": gap_closed, "evasion_unexpected_misses": unexpected_miss,
        "recall_by_tactic": {k: {**v, "recall": round(v["detected"] / v["scenarios"], 3)} for k, v in sorted(by_tactic.items())},
    }
    checks = {
        "attack_recall_min": metrics["recall"] >= gates["attack_recall_min"],
        "precision_min": metrics["precision"] >= gates["precision_min"],
        "benign_fpr_max": metrics["false_positive_rate"] <= gates["benign_fpr_max"],
        "mapping_accuracy_min": metrics["mapping_accuracy"] >= gates["mapping_accuracy_min"],
        "chain_recall_min": metrics["chain_recall"] >= gates["chain_recall_min"],
        "chain_negative_pass_min": metrics["chain_negative_pass"] >= gates["chain_negative_pass_min"],
        "no_unexpected_evasion_misses": not unexpected_miss,
    }
    if "events" in res.get("latency_ms", {}):
        checks["engine_event_p95_ms_max"] = res["latency_ms"]["p95"] <= gates["engine_event_p95_ms_max"]
    return {"metrics": metrics, "gate_checks": checks, "passed": all(checks.values())}


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=BACKEND, text=True).strip()
    except Exception:
        return "unknown"


def coverage_matrix(res: dict[str, Any]) -> dict[str, Any]:
    from app.detection import attack_catalog
    from app.detection.engine import get_engine

    ruled: dict[str, list[str]] = {}
    for r in get_engine().rules:
        for t in r.techniques:
            ruled.setdefault(t, []).append(r.id)
    tested = {t for a in res["attacks"] for t in a["techniques"]}
    detected = {t for a in res["attacks"] if a["detected"] for t in a["techniques"]}
    rows = []
    for tac_id, tac in attack_catalog.TACTICS.items():
        techs = sorted(t for t, m in attack_catalog.TECHNIQUES.items() if tac_id in m["tactics"])
        rows.append({
            "tactic": tac_id, "name": tac, "catalog_techniques": len(techs),
            "with_rule": sum(1 for t in techs if t in ruled),
            "tested_by_scenario": sum(1 for t in techs if t in tested),
            "detected_in_validation": sum(1 for t in techs if t in detected),
            "no_rule": [t for t in techs if t not in ruled],
            "rule_but_untested": [t for t in techs if t in ruled and t not in tested],
        })
    return {"tactics": rows}


def render_markdown(report: dict[str, Any]) -> str:
    m, env, s = report["summary"]["metrics"], report["environment"], report["summary"]
    L = ["# ThreatBrain validation report", "",
         f"* Result: **{'PASS' if s['passed'] else 'FAIL'}**  · mode `{env['mode']}` · commit `{env['git_sha']}` · rules `{env['rules_version']}` ({env['rule_count']} rules) · {env['generated_at']}",
         f"* Fidelity: {env['fidelity']}", ""]
    L += ["## Headline metrics", "", "| Metric | Value |", "|---|---|"]
    for k in ("attack_scenarios", "true_positives", "false_negatives", "benign_scenarios", "false_positives",
              "recall", "precision", "f1", "false_positive_rate", "mapping_accuracy", "chain_recall", "chain_negative_pass"):
        L.append(f"| {k} | {m[k]} |")
    L += ["", "## Gates", "", "| Gate | Result |", "|---|---|"]
    L += [f"| {k} | {'pass' if v else '**FAIL**'} |" for k, v in s["gate_checks"].items()]
    L += ["", "## Recall by tactic", "", "| Tactic | Scenarios | Detected | Recall |", "|---|---|---|---|"]
    L += [f"| {k} | {v['scenarios']} | {v['detected']} | {v['recall']} |" for k, v in m["recall_by_tactic"].items()]
    misses = [a for a in report["results"]["attacks"] if not a["detected"] and not a.get("known_gap")]
    L += ["", "## Missed attack scenarios", ""] + ([f"* `{a['id']}` {a['name']} ({', '.join(a['techniques'])})" for a in misses] or ["* none"])
    gaps = m.get("accepted_gaps", [])
    L += ["", "## Accepted detection gaps (excluded from recall; reason documented)", ""] + (
        [f"* `{g['id']}` {g['name']}: {g['reason'] or 'no reason given'}{' (NOW DETECTED: remove known_gap)' if g['now_detected'] else ''}" for g in gaps] or ["* none"])
    fps = [b for b in report["results"]["benign"] if b["false_positive"]]
    L += ["", "## False positives on benign hard negatives", ""] + ([f"* `{b['id']}` {b['name']} -> {', '.join(b['rules'])}" for b in fps] or ["* none"])
    badmap = [a for a in report["results"]["attacks"] if a["detected"] and not a["mapping_ok"]]
    L += ["", "## Detected but mapped to a different technique family", ""] + ([f"* `{a['id']}` {a['name']} expected {a['techniques']} got rules {a['rules']}" for a in badmap] or ["* none"])
    L += ["", "## Evasion probes", "", f"{m['evasion_detected']}/{m['evasion_probes']} detected. Open documented gaps: {m['evasion_known_gaps_open']}."]
    L += [f"* `{e['id']}` {e['name']}: {'detected' if e['detected'] else 'MISSED'}{' (known gap)' if e.get('known_gap') else ''}" for e in report["results"]["evasion"]]
    if m["evasion_gaps_closed"]:
        L += ["", f"**Gaps closed (remove `known_gap`)**: {m['evasion_gaps_closed']}"]
    chains = report["results"]["chains"] + report["results"]["chains_negative"]
    L += ["", "## Campaign correlation", ""] + [f"* `{c['id']}` {c['name']}: {'pass' if c['passed'] else '**FAIL**'} (fired {c['fired']})" for c in chains]
    lat = report["results"]["latency_ms"]
    L += ["", "## Latency", "", f"`{json.dumps(lat)}`"]
    if "llm" in report["results"]:
        L += ["", "## LLM", "", f"`{json.dumps(report['results']['llm'])}`"]
    L += ["", "## ATT&CK coverage (catalog subset)", "", "| Tactic | Catalog | With rule | Tested | Detected |", "|---|---|---|---|---|"]
    L += [f"| {r['name']} | {r['catalog_techniques']} | {r['with_rule']} | {r['tested_by_scenario']} | {r['detected_in_validation']} |"
          for r in report["coverage"]["tactics"]]
    L += ["", "## Limitations of this benchmark", ""] + [f"* {x}" for x in report["limitations"]]
    return "\n".join(L) + "\n"


LIMITATIONS = [
    "Scenarios were authored by the same team that wrote the rules; they are modelled on public emulation procedures but are NOT an independent benchmark. Scores will overstate real-world detection.",
    "All telemetry is synthetic event data. No real malware, credentials, or exploitation were used, and no attack command was executed.",
    "Benign hard negatives are a small hand-picked set (70). Production false-positive rates depend on your environment and must be measured on your own telemetry.",
    "LLM quality is not measured: the pipeline runs with a scripted model and an in-memory database stand-in. No live Groq/Supabase behaviour is verified by this report.",
    "Detection is per-event and sequence/threshold correlation within a window; it does not model statistical baselines or UEBA.",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["engine", "pipeline"], default="engine")
    ap.add_argument("--out", default=str(ROOT / "reports"))
    ap.add_argument("--gate", action="store_true", help="exit non-zero when a gate fails")
    args = ap.parse_args()

    gates = yaml.safe_load((ROOT / "gates.yaml").read_text())["gates"]
    res = run_engine() if args.mode == "engine" else run_pipeline()
    summary = summarize(res, gates)
    fidelity = ("detection engine + correlation only; no database, no LLM" if args.mode == "engine" else
                "real FastAPI app, durable queue and worker; in-memory PostgREST stand-in; scripted LLM (no live services)")
    report = {
        "schema": "threatbrain.validation/1",
        "environment": {
            "mode": args.mode, "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "git_sha": git_sha(), "python": platform.python_version(), "platform": platform.platform(),
            "rule_count": res.get("rule_count"), "rules_version": res.get("rules_version"), "fidelity": fidelity,
        },
        "gates": gates, "summary": summary, "results": res, "coverage": coverage_matrix(res), "limitations": LIMITATIONS,
    }
    if args.mode == "pipeline":
        from app.detection.engine import get_engine
        report["environment"]["rule_count"] = len(get_engine().rules)
        report["environment"]["rules_version"] = get_engine().version
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"validation_report.{args.mode}.json").write_text(json.dumps(report, indent=2, default=str))
    (out / f"validation_report.{args.mode}.md").write_text(render_markdown(report))
    m = summary["metrics"]
    print(f"[{args.mode}] attacks {m['true_positives']}/{m['attack_scenarios']} recall={m['recall']} precision={m['precision']} "
          f"fpr={m['false_positive_rate']} mapping={m['mapping_accuracy']} chains={m['chain_recall']}/{m['chain_negative_pass']} "
          f"-> {'PASS' if summary['passed'] else 'FAIL'}")
    for k, v in summary["gate_checks"].items():
        if not v:
            print(f"  gate failed: {k}")
    return 0 if (summary["passed"] or not args.gate) else 1


if __name__ == "__main__":
    raise SystemExit(main())
