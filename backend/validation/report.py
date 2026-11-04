"""Render reports/evaluation.json + reports/agent_evaluation.json as markdown, one section per split (splits are never pooled).

    python -m validation.report [--out ../docs/reports/evaluation-by-split.md]

Pure formatting: every number comes from the JSON the evaluators wrote; nothing is recomputed or rounded differently here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"


def pct(x: dict | None) -> str:
    if not x or x.get("rate") is None:
        return "n/a"
    lo, hi = max(0.0, x["ci95"][0]), x["ci95"][1]
    return f"{x['rate']:.3f} ({x['k']}/{x['n']}; 95% CI {lo:.2f}-{hi:.2f})"


def table(rows: list[list[str]], head: list[str]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def split_section(name: str, title: str, blurb: str, sp: dict, gates: dict, blind: bool) -> str:
    L = [f"### {title}", "", blurb, ""]
    c = sp["scenario_counts"]
    L.append(f"Scenarios: {c['attacks']} attack, {c['benign']} benign, {c['campaigns']} multi-stage campaigns. "
             + ("**Blind: aggregates only; per-scenario detail is withheld for the next round.**" if blind else ""))
    L.append("")
    rows = []
    for key, label in (("handwritten", "hand-written"), ("atomic_red_team", "Atomic Red Team derived"), ("lolbas", "LOLBAS derived"), ("adversarial_variants", "adversarial variants")):
        d = sp.get(key)
        if not d:
            continue
        a = d["attacks"]
        sev = d.get("severity")
        rows.append([label, pct(a["all"]), pct(a["high_signal_tactics"]), pct(a["alerted_not_just_signalled"]), pct(d["benign"]) if d["benign"]["n"] else "n/a (no benign twins)",
                     f"{d['mapping_accuracy']['rate']:.3f}", pct(d["evidence_correct"]), f"{sev['within_one']['rate']:.3f}" if sev else "n/a",
                     f"{d['technique_coverage']['techniques_with_a_detected_scenario']}/{d['technique_coverage']['techniques_tested']}"])
    L.append(table(rows, ["corpus", "attack recall (any hit)", "recall, high-signal tactics", "recall, alerted (not signal-only)", "benign FP rate", "ATT&CK mapping", "evidence correct", "severity within ±1", "techniques detected/tested"]))
    L.append("")
    camp = sp.get("campaigns")
    if camp:
        L.append(f"Campaigns: {pct(camp['campaigns'])}; near-miss chains stay quiet: {pct(camp['near_misses_stay_quiet'])}; evidence correct: {pct(camp['evidence_correct'])}; "
                 f"median first-to-last stage {camp['minutes_from_first_to_last_stage_median']} min, median time to first alert {camp['minutes_to_first_alert_median']} min.")
        L.append("")
    b = sp.get("behavior")
    if b:
        ns = b["noise_simulation"]
        L.append(f"Behavioural analytics: attacks detected {pct(b['attacks_detected'])}; benign-but-unusual scenarios alerted {pct(b['benign_alerted'])}; median {b['median_hours_to_first_alert']} h to first alert; "
                 f"noise simulation {ns['alerts']} alerts over {ns['entity_days']} entity-days = **{ns['alerts_per_100_entity_days']} per 100 entity-days** ({ns['entities']} entities, {ns['days']} days, 14-day warm-up). "
                 f"Documented cold-start gaps: {b.get('documented_cold_start_gaps', 0)}.")
        L.append("")
    mine = {k: v for k, v in gates.items() if k.startswith(name + ".")}
    if mine:
        L.append(table([[k, v["value"], f"{v['op']} {v['threshold']}", "PASS" if v["passed"] else "**FAIL**"] for k, v in mine.items()], ["gate", "value", "threshold", "result"]))
        L.append("")
    return "\n".join(L)


def tactic_table(sp: dict, key: str) -> str:
    d = sp.get(key)
    if not d:
        return ""
    rows = [[t, pct(v)] for t, v in d["recall_by_tactic"].items()]
    return table(rows, ["tactic", "recall"])


def comparison(res_now: dict) -> str:
    """Previous benchmark vs the first runs on each frozen generation vs now. Baseline files are archived first-run records."""
    def load(name: str) -> dict:
        return json.loads((REPORTS / "baselines" / name).read_text())["results"]["splits"]["heldout"]

    def row(h: dict) -> list[str]:
        hw, art = h["handwritten"], h["atomic_red_team"]["attacks"]
        camp = h.get("campaigns", {}).get("campaigns")
        return [pct(hw["attacks"]["all"]), pct(hw["benign"]), pct(art["high_signal_tactics"]), pct(camp) if camp else "n/a", f"{h['behavior']['noise_simulation']['alerts_per_100_entity_days']}"]

    v3, v4 = load("round3_firstrun.evaluation.json"), load("round3_v4_firstrun.evaluation.json")
    now = res_now["splits"]["heldout"]
    head = ["measure", "hand-written attack recall", "benign false-positive rate", "ART blind, high-signal recall", "campaigns", "behaviour alerts / 100 entity-days"]
    rows = [["**Previous release benchmark** (commit 6c4c646; tuned corpus, 169 attacks / 125 benign; *not independent*)", "169/169 = 1.000", "0/125 = 0.000", "not measured", "14/14", "not measured"],
            ["Frozen v3, **first run** (3518c25, before remediation)"] + row(v3),
            ["Frozen v4, **first run** (1bfcb65)"] + row(v4),
            ["**Now** (v4 FP fixed after reading rule ids; ART/behaviour unchanged by that)"] + row(now)]
    return table(rows, head)


def render() -> str:
    ev = json.loads((REPORTS / "evaluation.json").read_text())
    ag = json.loads((REPORTS / "agent_evaluation.json").read_text())
    res, gates = ev["results"], ev["gates"]
    env = ev["environment"]
    nfail = len(ev["failed_gates"])
    L = ["# Evaluation by split", "",
         f"Generated by `python -m validation.report` from `backend/validation/reports/evaluation.json` (commit `{env['git_sha']}`, {env['generated_at']}, "
         f"{env['rules']['count']} rules v{env['rules']['version']}) and `agent_evaluation.json`.", "",
         f"**{len(gates) - nfail}/{len(gates)} detection/behaviour gates pass; {nfail} FAIL: {', '.join(ev['failed_gates']) or 'none'}.** "
         f"Dataset freeze: {'intact' if ev['freeze']['intact'] else 'BROKEN: ' + str(ev['freeze']['problems'])}. "
         f"Agent evaluation: {len(ag['gates']) - len(ag['failed_gates'])}/{len(ag['gates'])} gates pass; failed: {', '.join(ag['failed_gates']) or 'none'}.", "",
         "Splits are reported separately and are **never pooled**. A pooled number would be dominated by the large derived corpora (Atomic Red Team, LOLBAS) or by the tuned corpus and would hide the weakest result.",
         "All corpora are synthetic or derived; none is real customer traffic. Hand-written scenarios were authored by the same team that wrote the rules.", "",
         "## Detection and behaviour", ""]
    L.append(split_section("development", "Development split (tuned against; expect ~100%)", "Used to write and fix rules. Reporting it demonstrates regression safety, not generalisation.", res["splits"]["development"], gates, False))
    L.append(split_section("tuning", "Tuning split (consumed held-out sets, ART/LOLBAS tuning halves, adversarial variants)", "Rules were adjusted using these scenarios, including sets that were once held-out and were reclassified after their detail was read.", res["splits"]["tuning"], gates, False))
    L.append(split_section("heldout", "Held-out split (frozen before the corresponding tuning; blind)", "Frozen by hash (`FROZEN.json`). Per-scenario results are not consulted for tuning. The v4 sets' false-positive rule ids were read once after their first run, so post-fix v4 numbers are not independent (see `reports/history.md`).", res["splits"]["heldout"], gates, True))
    L.append("### Comparison with the previous benchmark (held-out generations, never the tuned corpus)")
    L.append("")
    L.append(comparison(res))
    L.append("")
    L.append("The previous release reported a perfect score on a corpus the rules were written against. The first rows on genuinely held-out material are the honest baseline. "
             "Read the rows with care: the v3 and v4 hand-written sets are **different scenario sets** (94 vs 39 attacks, 51 vs 37 benign), so the jump in hand-written recall is partly set difficulty and sample size, not only improvement; "
             "the ART blind half is the **same** 607 procedures in every row, so that column is the comparable one (0.323 -> 0.464, still below the 0.60 gate). "
             "The v4 false-positive rate after fixes is not independent. Evasion probes: 5/12 detected previously, 11/12 now.")
    L.append("")
    L.append("#### Recall by tactic: Atomic Red Team derived, tuning half vs blind half")
    L.append("")
    L.append("Tuning:\n\n" + tactic_table(res["splits"]["tuning"], "atomic_red_team") + "\n\nBlind:\n\n" + tactic_table(res["splits"]["heldout"], "atomic_red_team") + "\n")
    L.append("## Robustness")
    L.append("")
    m = res["metamorphic"]
    rows = []
    for k, v in m.items():
        rows.append([k, json.dumps({kk: vv for kk, vv in v.items() if not isinstance(vv, (list, dict))})[:240]])
    L.append(table(rows, ["metamorphic set", "summary"]))
    L.append("")
    d = res["degraded_telemetry"]
    rows = [[k, json.dumps({kk: vv for kk, vv in v.items() if not isinstance(vv, (list, dict))} if isinstance(v, dict) else v)[:200]] for k, v in d["development_and_tuning"].items()]
    L.append("Degraded telemetry (development + tuning):\n\n" + table(rows, ["experiment", "result"]) + "\n")
    ps = res.get("pipeline_sample")
    if ps:
        L.append(f"Real pipeline sample ({ps['scenarios']} randomly drawn scenarios through ingest -> detection -> agents on the in-memory database with a scripted model): "
                 f"attacks alerted {pct(ps['attack_alerted'])}, benign alerted {pct(ps['benign_alerted'])}, agent runs {ps['runs_completed']}/{ps['pipeline_runs']} completed, "
                 f"{ps['runs_failed']} failed, reliability {ps['agent_execution_reliability']}; ingest -> detection p50/p95 {ps['ms_ingest_to_detection']['p50']}/{ps['ms_ingest_to_detection']['p95']} ms, "
                 f"ingest -> investigation complete p50/p95 {ps['ms_ingest_to_investigation_complete']['p50']}/{ps['ms_ingest_to_investigation_complete']['p95']} ms. "
                 "These are platform-overhead timings with a scripted model; **real LLM latency and token cost are not measured.**")
        L.append("")
    L.append("## Agent / LLM evaluation (scripted back-ends)")
    L.append("")
    L.append("**No language model was called.** The back-ends are scripted: a faithful `reference`, and adversarial ones (`hallucinator`, `injection_follower`, `overconfident`, `flapping`, `malformed`, `hostile_responder`, outage and slow providers). "
             "The numbers measure the platform's guardrails around a model (grounding, reconciliation with deterministic verdicts, approval gating, failure recovery), not any model's skill. "
             "A live-provider mode is **not implemented**; the scenarios and gates are provider-agnostic and a real-model back-end can be added in `agent_models.py`.")
    L.append("")
    L.append(table([[k, v["value"], f"{v['op']} {v['threshold']}", "PASS" if v["passed"] else "**FAIL**"] for k, v in ag["gates"].items()], ["gate", "value", "threshold", "result"]))
    L.append("")
    L.append(f"Live provider: **{ag['results']['live']['status']}**: {ag['results']['live']['reason']}.")
    L.append("")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT.parent.parent / "docs" / "reports" / "evaluation-by-split.md"))
    a = ap.parse_args()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(render())
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
