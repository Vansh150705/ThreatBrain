"""Turn LOLBAS (Living Off The Land Binaries, Scripts and Libraries) command examples into synthetic telemetry. NOTHING IS EXECUTED.

LOLBAS (https://github.com/LOLBAS-Project/LOLBAS) is GPL-3.0 licensed data maintained by its community, with ATT&CK ids per command. Because of
the licence, the derived scenario file is NOT committed: this tool fetches the YAML files to a cache and writes
``validation/scenarios/external/lolbas_derived.yaml`` (git-ignored). ``validation.evaluate`` includes it when present and states plainly that it
was not run when absent.

    python -m validation.tools.import_lolbas --fetch

Placeholders such as ``{REMOTEURL:.exe}`` are replaced by documentation-range addresses and neutral paths. Split rule (fixed in advance):
sha256(binary + command) parity, even = tuning, odd = blind.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BACKEND = ROOT.parent
sys.path.insert(0, str(BACKEND))

from app.detection import attack_catalog  # noqa: E402

OUT = ROOT / "scenarios" / "external" / "lolbas_derived.yaml"
NAMES = HERE / "lolbas_names.txt"
BASE = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/yml/{kind}/{name}.yml"


def fetch(dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    n = 0
    for line in NAMES.read_text().split():
        kind, _, name = line.partition(":")
        try:
            with urllib.request.urlopen(BASE.format(kind=kind, name=name), timeout=30) as r:   # noqa: S310 - fixed https URL
                (dest / f"{kind}_{name}.yml").write_bytes(r.read())
            n += 1
        except Exception:
            pass
    return n


def fill(cmd: str) -> str:
    def sub(m: re.Match[str]) -> str:
        kind, _, ext = m.group(1).partition(":")
        ext = ext or ""
        if kind == "REMOTEURL":
            return f"http://203.0.113.50/payload{ext}"
        if kind == "PATH_SMB":
            return f"\\\\203.0.113.50\\share\\payload{ext}"
        if kind == "PATH_ABSOLUTE":
            return f"C:\\Users\\Public\\payload{ext}"
        if kind == "PATH":
            return f"C:\\Users\\Public\\payload{ext}"
        if kind == "CMD":
            return "cmd.exe /c whoami"
        if kind == "REGEX":
            return "regex"
        return f"C:\\Users\\Public\\x{ext}"

    return re.sub(r"\{([A-Z_]+(?::[^}]*)?)\}", sub, cmd)


def build(src: Path) -> dict:
    scenarios = []
    for path in sorted(src.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        binary = str(doc.get("Name", path.stem))
        for i, c in enumerate(doc.get("Commands") or [], 1):
            cmd = str(c.get("Command", "")).strip()
            if not cmd or "\n" in cmd:
                continue
            command = fill(cmd)
            tid = str(c.get("MitreID") or "")
            tid = tid if tid in attack_catalog.TECHNIQUES else ""
            tactic = (attack_catalog.tactics_for([tid]) or [""])[0] if tid else ""
            h = int(hashlib.sha256((binary + command).encode()).hexdigest(), 16)
            exe = re.split(r"[\\/]", command.split()[0].strip("\"'"))[-1]
            scenarios.append({
                "id": f"LOL-{path.stem}-{i:02d}", "name": f"{binary}: {str(c.get('Usecase', ''))[:80]}", "techniques": [tid] if tid else [],
                "tactic": tactic, "category": str(c.get("Category", "")), "split": "tuning" if h % 2 == 0 else "blind",
                "events": [{"title": "Process creation", "event_type": "process.start", "asset_name": "lolbas-win-01", "process_name": exe, "command_line": command}],
            })
    return {"meta": {"source": "LOLBAS-Project/LOLBAS (GPL-3.0); derived data not redistributed in this repository", "split_rule": "sha256(binary+command) even=tuning odd=blind"},
            "scenarios": scenarios}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--from-dir", type=Path)
    a = ap.parse_args()
    src = a.from_dir
    if a.fetch:
        src = Path("/tmp/lolbas_fetch")
        print("fetched", fetch(src))
    if not src:
        ap.error("need --fetch or --from-dir")
    doc = build(src)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("# GENERATED, NOT COMMITTED (GPL-3.0 source data). See validation/tools/import_lolbas.py\n" + yaml.safe_dump(doc, sort_keys=False, width=200), encoding="utf-8")
    print(len(doc["scenarios"]), "scenarios ->", OUT)


if __name__ == "__main__":
    main()
