"""Overlap between the datasets: how independent are the held-out sets really?

    python -m validation.leakage [--gate]

For every scenario in the held-out split the nearest scenario in the development+tuning splits is found (Jaccard similarity of the
tokens of its attacker-controlled text). A held-out set that is mostly near-copies of what the rules were built against measures memorisation,
not generalisation. Also checked: exact duplicates across splits, and whether a held-out command appears verbatim in the rule file's own test events.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent
sys.path.insert(0, str(BACKEND))

from validation import corpus  # noqa: E402

TOKEN = re.compile(r"[a-z0-9_.:/\\$%@-]{2,}")
NEAR, VERY_NEAR = 0.8, 0.9
GATES = {"handwritten_heldout_exact_duplicates_max": 0, "handwritten_heldout_near_duplicate_rate_max": 0.05}


def text_of(sc: dict[str, Any]) -> str:
    parts: list[str] = []
    for ev in sc.get("events", []):
        if "payload" in ev:
            parts.append(json.dumps(ev["payload"], sort_keys=True, default=str))
            continue
        for k in ("command_line", "process_name", "event_type", "username", "asset_name", "source_ip", "destination_ip", "destination_port"):
            if ev.get(k) is not None:
                parts.append(str(ev[k]))
        raw = ev.get("raw_data") or {}
        parts.append(json.dumps(raw, sort_keys=True, default=str))
    return " ".join(parts).lower()


def tokens(t: str) -> frozenset[str]:
    return frozenset(TOKEN.findall(t))


def jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def analyse() -> dict[str, Any]:
    items = corpus.load_corpus(roles={"attack", "benign", "chain", "chain_negative", "behavior_attack", "behavior_benign"})
    known = [s for s in items if s["split"] in ("development", "tuning") and s["kind"] != "behavior"]
    held = [s for s in items if s["split"] == "heldout" and s["kind"] != "behavior"]
    index: dict[str, list[int]] = {}
    ktoks = [tokens(text_of(s)) for s in known]
    ktexts = [text_of(s) for s in known]
    for i, tk in enumerate(ktoks):
        for t in tk:
            index.setdefault(t, []).append(i)
    rules_text = (BACKEND / "app" / "detection" / "rules.yaml").read_text(encoding="utf-8").lower()
    groups: dict[str, list[dict[str, Any]]] = {}
    for s in held:
        txt = text_of(s)
        tk = tokens(txt)
        cand: dict[int, int] = {}
        for t in tk:
            if len(index.get(t, ())) > 400:      # ubiquitous token ("process.start"): useless for similarity
                continue
            for i in index.get(t, ()):
                cand[i] = cand.get(i, 0) + 1
        best, best_i = 0.0, -1
        for i in sorted(cand, key=lambda j: -cand[j])[:60]:
            sim = jaccard(tk, ktoks[i])
            if sim > best:
                best, best_i = sim, i
        cmd = next((e.get("command_line") for e in s.get("events", []) if e.get("command_line")), None)
        in_rules = bool(cmd) and len(str(cmd)) >= 24 and str(cmd).lower().replace("\\", "\\") in rules_text
        kind = "art" if s["id"].startswith("ART-") else "lolbas" if s["id"].startswith("LOL-") else "handwritten"
        groups.setdefault(kind, []).append({"id": s["id"], "max_similarity": round(best, 3), "nearest": known[best_i]["id"] if best_i >= 0 else None,
                                            "exact_duplicate": best_i >= 0 and txt == ktexts[best_i], "verbatim_in_rule_tests": in_rules})
    out: dict[str, Any] = {"definition": f"nearest development/tuning scenario by token Jaccard; near >= {NEAR}, very near >= {VERY_NEAR}", "groups": {}}
    for kind, rows in groups.items():
        sims = [r["max_similarity"] for r in rows]
        out["groups"][kind] = {
            "scenarios": len(rows), "median_max_similarity": round(statistics.median(sims), 3),
            "near_duplicates": sum(s >= NEAR for s in sims), "near_duplicate_rate": round(sum(s >= NEAR for s in sims) / len(rows), 4),
            "very_near_duplicates": sum(s >= VERY_NEAR for s in sims), "exact_duplicates": sum(r["exact_duplicate"] for r in rows),
            "verbatim_in_rule_tests": sum(r["verbatim_in_rule_tests"] for r in rows),
        }
    hw = out["groups"].get("handwritten", {"exact_duplicates": 0, "near_duplicate_rate": 0.0})
    out["gates"] = {
        "handwritten_heldout_exact_duplicates": {"value": hw["exact_duplicates"], "threshold": GATES["handwritten_heldout_exact_duplicates_max"], "op": "<=",
                                                 "passed": hw["exact_duplicates"] <= GATES["handwritten_heldout_exact_duplicates_max"]},
        "handwritten_heldout_near_duplicate_rate": {"value": hw["near_duplicate_rate"], "threshold": GATES["handwritten_heldout_near_duplicate_rate_max"], "op": "<=",
                                                    "passed": hw["near_duplicate_rate"] <= GATES["handwritten_heldout_near_duplicate_rate_max"]},
    }
    out["passed"] = all(g["passed"] for g in out["gates"].values())
    out["detail_private"] = {k: [r for r in v if r["max_similarity"] >= NEAR or r["exact_duplicate"] or r["verbatim_in_rule_tests"]][:80] for k, v in groups.items()}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "reports"))
    a = ap.parse_args()
    res = analyse()
    detail = res.pop("detail_private")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "leakage.json").write_text(json.dumps(res, indent=1))
    (out / "heldout.leakage.detail.json").write_text(json.dumps(detail, indent=1))
    for k, v in res["groups"].items():
        print(f"{k:12s} n={v['scenarios']:4d} median-sim={v['median_max_similarity']:.2f} near={v['near_duplicates']} ({v['near_duplicate_rate']:.1%}) exact={v['exact_duplicates']} in-rule-tests={v['verbatim_in_rule_tests']}")
    print("leakage gates:", "PASS" if res["passed"] else "FAIL")
    return 1 if a.gate and not res["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
