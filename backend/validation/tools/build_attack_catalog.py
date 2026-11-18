"""Regenerate app/detection/attack_full.json from MITRE's published STIX bundle.

    curl -o enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python -m validation.tools.build_attack_catalog enterprise-attack.json

Revoked and deprecated techniques are dropped. v20 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112); both are
recorded as TA0005 here so that tactic ids already used by rules, reports and stored threats keep their meaning.
ATT&CK is (c) The MITRE Corporation; used under the ATT&CK Terms of Use.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "app" / "detection" / "attack_full.json"
MERGE = {"stealth": "TA0005", "defense-impairment": "TA0005"}


def main(src: str) -> None:
    objs = json.loads(Path(src).read_text())["objects"]
    coll = next(o for o in objs if o["type"] == "x-mitre-collection")
    tac = {o["x_mitre_shortname"]: next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
           for o in objs if o["type"] == "x-mitre-tactic"}
    tmap = {k: MERGE.get(k, v) for k, v in tac.items()}
    out = {}
    for o in objs:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
        tactics: list[str] = []
        for ph in o.get("kill_chain_phases", []):
            t = tmap.get(ph["phase_name"]) if ph["kill_chain_name"] == "mitre-attack" else None
            if t and t not in tactics:
                tactics.append(t)
        out[tid] = [o["name"], tactics]
    doc = {"source": "MITRE ATT&CK Enterprise (attack-stix-data)", "attack_version": coll.get("x_mitre_version"), "modified": coll.get("modified"),
           "techniques": dict(sorted(out.items()))}
    OUT.write_text(json.dumps(doc, separators=(",", ":")))
    print(len(out), "techniques ->", OUT)


if __name__ == "__main__":
    main(sys.argv[1])
