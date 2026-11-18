"""ATT&CK coverage matrix over the WHOLE Enterprise framework (v20 data in app/detection/attack_full.json).

    python -m validation.coverage [--out ../docs/reports]

Three different questions, never merged into one number:
  * has a rule or correlation?   (static: rules.yaml / correlations.yaml name the technique, or one of its sub-techniques)
  * was it tested?               (a scenario in the registry is labelled with it; held-out is counted, never listed)
  * was it detected when tested? (any hit on at least one scenario of that technique)
A technique "tested and detected" is evidence that a CASE is covered, not that the technique is.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent
sys.path.insert(0, str(BACKEND))

from app.detection import attack_catalog  # noqa: E402
from app.detection.correlation import load_correlations  # noqa: E402
from app.detection.engine import get_engine  # noqa: E402
from validation import corpus  # noqa: E402
from validation.evaluate import detect_scenario, git_sha  # noqa: E402


def parent(t: str) -> str:
    return t.split(".")[0]


def build() -> dict[str, Any]:
    engine = get_engine()
    rule_ids: dict[str, set[str]] = {}
    for r in engine.rules:
        for t in r.techniques:
            rule_ids.setdefault(t, set()).add(r.id)
    for c in load_correlations():
        for t in c.techniques:
            rule_ids.setdefault(t, set()).add(c.id)
    tested: dict[str, dict[str, int]] = {}
    detected: dict[str, dict[str, int]] = {}
    for sc in corpus.load_corpus(roles={"attack"}):
        hits, _ = detect_scenario(engine, sc)
        for t in sc.get("techniques", []):
            tested.setdefault(t, {}).setdefault(sc["split"], 0)
            tested[t][sc["split"]] += 1
            if hits:
                detected.setdefault(t, {}).setdefault(sc["split"], 0)
                detected[t][sc["split"]] += 1

    def covered(t: str) -> bool:
        return t in rule_ids or any(r == t or r.startswith(t + ".") for r in rule_ids)

    rows = []
    for tid, meta in sorted(attack_catalog.TECHNIQUES.items()):
        rows.append({
            "id": tid, "name": meta["name"], "tactics": meta["tactics"], "sub_technique": "." in tid,
            "rules": sorted(rule_ids.get(tid, [])), "has_rule": covered(tid),
            "tested": {k: v for k, v in tested.get(tid, {}).items()},
            "detected": {k: v for k, v in detected.get(tid, {}).items()},
        })
    tactics = []
    for tac_id, name in attack_catalog.TACTICS.items():
        rs = [r for r in rows if tac_id in r["tactics"]]
        parents = [r for r in rs if not r["sub_technique"]]
        tactics.append({
            "tactic": tac_id, "name": name, "techniques": len(rs), "parent_techniques": len(parents),
            "with_rule_or_correlation": sum(r["has_rule"] for r in rs), "parents_with_rule": sum(r["has_rule"] for r in parents),
            "tested_dev_or_tuning": sum(1 for r in rs if r["tested"].get("development") or r["tested"].get("tuning")),
            "detected_dev_or_tuning": sum(1 for r in rs if r["detected"].get("development") or r["detected"].get("tuning")),
            "tested_heldout": sum(1 for r in rs if r["tested"].get("heldout")),
            "detected_heldout": sum(1 for r in rs if r["detected"].get("heldout")),
            "no_rule": [r["id"] for r in parents if not r["has_rule"]],
        })
    return {"schema": "threatbrain.attack_coverage/1", "git_sha": git_sha(), "attack_catalog": attack_catalog.FULL_CATALOG_VERSION,
            "rules": len(engine.rules), "rule_version": engine.version, "correlations": len(load_correlations()), "tactics": tactics, "techniques": rows,
            "totals": {"techniques": len(rows), "parent_techniques": sum(not r["sub_technique"] for r in rows), "with_rule": sum(r["has_rule"] for r in rows),
                       "parents_with_rule": sum(r["has_rule"] for r in rows if not r["sub_technique"])}}


def markdown(cov: dict[str, Any]) -> str:
    t = cov["totals"]
    L = ["# ATT&CK coverage matrix", "",
         f"* Catalogue: {cov['attack_catalog']} (all non-revoked Enterprise techniques); {cov['rules']} rules (version {cov['rule_version']}) and {cov['correlations']} correlations; commit `{cov['git_sha']}`.",
         f"* **{t['parents_with_rule']} of {t['parent_techniques']} parent techniques** ({t['parents_with_rule'] / t['parent_techniques']:.0%}) and {t['with_rule']} of {t['techniques']} techniques including sub-techniques have at least one rule or correlation. "
         "Having a rule is not the same as detecting an attack that uses the technique; see the other columns.", "",
         "Columns: *rule* = a rule or correlation names the technique (or one of its sub-techniques); *tested* = at least one labelled scenario exists; *detected* = at least one of those scenarios produced a hit. "
         "Held-out counts are numbers only: which techniques failed is not published here, to keep that set usable for the next round.", "",
         "| Tactic | Techniques | With rule | Parents with rule | Tested (dev/tuning) | Detected (dev/tuning) | Tested (held-out) | Detected (held-out) |", "|---|---|---|---|---|---|---|---|"]
    for r in cov["tactics"]:
        L.append(f"| {r['tactic']} {r['name']} | {r['techniques']} | {r['with_rule_or_correlation']} | {r['parents_with_rule']}/{r['parent_techniques']} | {r['tested_dev_or_tuning']} | {r['detected_dev_or_tuning']} | {r['tested_heldout']} | {r['detected_heldout']} |")
    L += ["", "## Parent techniques without any rule, by tactic", ""]
    for r in cov["tactics"]:
        if r["no_rule"]:
            names = {x["id"]: x["name"] for x in cov["techniques"]}
            L.append(f"* **{r['name']}** ({len(r['no_rule'])}): " + ", ".join(f"{i} {names[i]}" for i in r["no_rule"][:40]) + (" …" if len(r["no_rule"]) > 40 else ""))
    L += ["", "## Reading this honestly", "",
          "* A command-line and log-event detection engine cannot see most Resource Development, Reconnaissance (pre-compromise) or purely network/physical techniques; those gaps are structural, not backlog.",
          "* Techniques with a rule may still be detected only in the forms the rule authors thought of; the evaluation report measures that on independent corpora.",
          "* Behavioural detections (UEBA) map to a few techniques (T1078, T1021, T1098, T1530, T1213, T1041, T1048, T1071) and are listed under those, but they detect deviations, not the technique itself."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(BACKEND.parent / "docs" / "reports"))
    a = ap.parse_args()
    cov = build()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "attack-coverage.json").write_text(json.dumps(cov, indent=1))
    (out / "attack-coverage.md").write_text(markdown(cov))
    t = cov["totals"]
    print(f"{t['parents_with_rule']}/{t['parent_techniques']} parent techniques have a rule; {t['with_rule']}/{t['techniques']} including sub-techniques")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
