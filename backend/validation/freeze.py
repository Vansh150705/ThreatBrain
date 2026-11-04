"""Freeze and verify the held-out datasets.

A held-out set is only evidence of generalisation while nobody tunes against it. This tool makes that checkable:

    python -m validation.freeze --check                     # exit 1 if a frozen file/subset changed
    python -m validation.freeze --refreeze --reason "..."   # deliberate re-freeze: recorded, with a reason, in FROZEN.json

Frozen entries are whole files, or the ``split: blind`` subset of a file (Atomic Red Team scenarios). The hash is of the
canonical JSON of the scenarios, so reformatting a file is harmless but changing a scenario is not. CI and the release
gates run ``--check``; a re-freeze is a reviewable diff of FROZEN.json and must be accompanied by a validation/reports/history.md entry
that says why the set is no longer blind.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
SCEN = ROOT / "scenarios"
FROZEN = ROOT / "FROZEN.json"

# (file, selector) - selector None = every scenario; "blind" = scenarios with split: blind
TARGETS = [
    ("heldout_v3.yaml", None),
    ("heldout_v3_chains.yaml", None),
    ("adversarial_unseen.yaml", None),
    ("behavior_heldout.yaml", None),
    ("heldout_v4.yaml", None),
    ("heldout_v4_chains.yaml", None),
    ("behavior_heldout_v4.yaml", None),
    ("art_derived.yaml", "blind"),
]


def digest(file: str, selector: str | None) -> tuple[str, int]:
    doc = yaml.safe_load((SCEN / file).read_text(encoding="utf-8"))
    items = doc["scenarios"]
    if selector:
        items = [s for s in items if s.get("split") == selector]
    blob = json.dumps(items, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest(), len(items)


def current() -> dict[str, dict]:
    out = {}
    for file, sel in TARGETS:
        h, n = digest(file, sel)
        out[f"{file}{'#' + sel if sel else ''}"] = {"sha256": h, "scenarios": n}
    return out


def check() -> list[str]:
    if not FROZEN.exists():
        return ["FROZEN.json is missing"]
    frozen = json.loads(FROZEN.read_text())["frozen"]
    now = current()
    problems = []
    for k, v in frozen.items():
        if k not in now:
            problems.append(f"{k}: no longer present")
        elif now[k]["sha256"] != v["sha256"]:
            problems.append(f"{k}: content changed since freeze ({v['scenarios']} -> {now[k]['scenarios']} scenarios)")
    for k in now:
        if k not in frozen:
            problems.append(f"{k}: not frozen")
    return problems


def refreeze(reason: str) -> None:
    prev = json.loads(FROZEN.read_text()) if FROZEN.exists() else {"history": []}
    doc = {
        "about": "Hashes of held-out datasets. See validation/freeze.py. A mismatch means a held-out set was edited; re-freezing is a deliberate, recorded act.",
        "frozen": current(),
        "history": [*prev.get("history", []), {"at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "reason": reason}],
    }
    FROZEN.write_text(json.dumps(doc, indent=2) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--refreeze", action="store_true")
    ap.add_argument("--reason", default="")
    a = ap.parse_args()
    if a.refreeze:
        if len(a.reason.strip()) < 10:
            ap.error("--reason (at least a sentence) is required to re-freeze")
        refreeze(a.reason)
        print("frozen:", json.dumps(current(), indent=1))
        return 0
    problems = check()
    for p in problems:
        print("FROZEN CHECK FAILED:", p)
    if not problems:
        print("frozen datasets unchanged:", ", ".join(json.loads(FROZEN.read_text())["frozen"]))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
