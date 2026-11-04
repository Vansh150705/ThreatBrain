"""Turn Atomic Red Team test definitions into synthetic telemetry scenarios. NOTHING IS EXECUTED.

Atomic Red Team (https://github.com/redcanaryco/atomic-red-team, MIT licence, (c) Red Canary) describes, for each ATT&CK
technique, the commands a tester would run in a lab. We treat those command strings purely as DATA: each becomes the
``command_line`` of a process event, which is fed through ThreatBrain's own ingestion and detection pipeline. The labels
(technique id, platform) come from the ART authors, not from this project's rule authors - that independence is the point.

    python -m validation.tools.import_art --fetch              # download the pinned technique list (needs network)
    python -m validation.tools.import_art --from-dir DIR       # rebuild scenarios from previously fetched YAML

Output: validation/scenarios/art_derived.yaml (committed, so tests and CI never need the network) with the source file
hash of every input, so a later re-import shows exactly which upstream files changed.

Split rule (fixed in advance, content-independent): sha256(auto_generated_guid) parity. Even -> ``tuning`` (rules may be
improved against these), odd -> ``blind`` (never used for tuning; reported separately). A scenario's split can therefore
never be chosen after seeing whether it is detected.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BACKEND = ROOT.parent
sys.path.insert(0, str(BACKEND))

from app.detection import attack_catalog  # noqa: E402

TECHNIQUES = HERE / "art_techniques.txt"
OUT = ROOT / "scenarios" / "art_derived.yaml"
RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{t}/{t}.yaml"
EXECUTORS = {"command_prompt": "cmd", "powershell": "ps", "sh": "sh", "bash": "sh"}
MAX_LINES = 6
LICENSE = (
    "Atomic Red Team is Copyright (c) 2018 Red Canary, Inc., MIT License "
    "(https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt). Command strings are reproduced as test data."
)


def split_of(guid: str) -> str:
    return "tuning" if int(hashlib.sha256(guid.encode()).hexdigest(), 16) % 2 == 0 else "blind"


def fetch(dest: Path) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    missing = []
    for t in [x.strip() for x in TECHNIQUES.read_text().split() if x.strip()]:
        try:
            with urllib.request.urlopen(RAW.format(t=t), timeout=30) as r:   # noqa: S310 - fixed https URL
                (dest / f"{t}.yaml").write_bytes(r.read())
        except Exception:
            missing.append(t)
    return missing


def substitute(cmd: str, args: dict[str, Any], windows: bool) -> str:
    def sub(m: re.Match[str]) -> str:
        spec = args.get(m.group(1)) or {}
        v = spec.get("default")
        return str(v) if v is not None else m.group(0)

    out = re.sub(r"#\{([^}]+)\}", sub, cmd)
    root = r"C:\AtomicRedTeam\atomics" if windows else "/opt/AtomicRedTeam/atomics"
    return out.replace("PathToAtomicsFolder", root)


def _exe(line: str) -> str:
    first = line.strip().split(None, 1)[0] if line.strip() else ""
    return re.split(r"[\\/]", first.strip("\"'"))[-1] or "cmd.exe"


def events_for(executor: str, command: str, windows: bool) -> list[dict[str, Any]]:
    lines = [ln.rstrip() for ln in command.strip().splitlines() if ln.strip() and not ln.strip().startswith(("#", "REM ", "rem "))]
    asset = "atomic-win-01" if windows else "atomic-lin-01"
    base = {"title": "Process creation", "event_type": "process.start", "asset_name": asset}
    kind = EXECUTORS[executor]
    if kind == "ps":
        script = " ".join(lines)[:4000]
        return [{**base, "process_name": "powershell.exe", "command_line": script}]
    if kind == "sh" and len(lines) > MAX_LINES:
        return [{**base, "process_name": "bash", "command_line": "; ".join(lines)[:4000]}]
    return [{**base, "process_name": _exe(ln) if kind == "cmd" else "bash", "command_line": ln[:4000]} for ln in lines[:MAX_LINES * 3]]


def build(src_dir: Path) -> dict[str, Any]:
    scenarios: list[dict[str, Any]] = []
    sources: dict[str, str] = {}
    for path in sorted(src_dir.glob("T*.yaml")):
        raw = path.read_bytes()
        sources[path.stem] = hashlib.sha256(raw).hexdigest()
        doc = yaml.safe_load(raw)
        tid = doc.get("attack_technique")
        if not tid:
            continue
        known = tid in attack_catalog.CATALOG if hasattr(attack_catalog, "CATALOG") else True
        for n, test in enumerate(doc.get("atomic_tests") or [], 1):
            ex = test.get("executor") or {}
            name = ex.get("name")
            platforms = test.get("supported_platforms") or []
            if name not in EXECUTORS or not ex.get("command") or not ({"windows", "linux"} & set(platforms)):
                continue
            windows = "windows" in platforms and name in ("command_prompt", "powershell")
            cmd = substitute(str(ex["command"]), test.get("input_arguments") or {}, windows)
            evs = events_for(name, cmd, windows)
            if not evs:
                continue
            guid = str(test.get("auto_generated_guid") or f"{tid}-{n}")
            primary = (attack_catalog.tactics_for([tid]) or [""])[0] if known else ""
            scenarios.append({
                "id": f"ART-{tid}-{n:02d}", "name": str(test.get("name"))[:120], "techniques": [tid], "tactic": primary,
                "platform": "windows" if windows else "linux", "art_guid": guid, "split": split_of(guid), "events": evs,
            })
    return {
        "meta": {"source": "Atomic Red Team", "licence": LICENSE, "imported": datetime.now(UTC).strftime("%Y-%m-%d"),
                 "split_rule": "sha256(auto_generated_guid) even=tuning odd=blind", "source_files": sources,
                 "note": "Telemetry is synthetic: ART command strings used as process command lines. Nothing was executed."},
        "scenarios": scenarios,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true", help="download the technique files to a temp dir first")
    ap.add_argument("--from-dir", type=Path)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()
    src = a.from_dir
    if a.fetch:
        src = Path("/tmp/art_fetch")
        print("missing:", fetch(src))
    if not src:
        ap.error("need --fetch or --from-dir")
    doc = build(src)
    a.out.write_text("# GENERATED by validation/tools/import_art.py - do not edit by hand.\n" + yaml.safe_dump(doc, sort_keys=False, width=200, allow_unicode=True), encoding="utf-8")
    by = {"tuning": 0, "blind": 0}
    for s in doc["scenarios"]:
        by[s["split"]] += 1
    print(f"{len(doc['scenarios'])} scenarios from {len(doc['meta']['source_files'])} technique files -> {a.out} {by}")


if __name__ == "__main__":
    main()
