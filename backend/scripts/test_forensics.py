"""Local test script for the Forensics Agent endpoint."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import jwt
import requests

from app.core.config import get_settings


def make_token(sub: str, email: str, *, secret: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": sub,
            "email": email,
            "aud": "authenticated",
            "role": "authenticated",
            "exp": now + 3600,
            "iat": now,
        },
        secret,
        algorithm="HS256",
    )


def main() -> None:
    settings = get_settings()
    jane_token = make_token(
        "00000000-0000-0000-0000-00000000a001",
        "jane.morrison@acme.example",
        secret=settings.SUPABASE_JWT_SECRET,
    )

    # Use one of your seeded demo incidents
    target = "INC-ACT001"  # APT29 SSH brute-force chain

    print(f"=== Reconstructing forensic timeline for {target} ===\n")
    r = requests.post(
        "http://localhost:8000/api/v1/agents/forensics/reconstruct",
        headers={"Authorization": f"Bearer {jane_token}"},
        json={"incident_short_id": target},
        timeout=180,
    )
    print(f"Status: {r.status_code}\n")

    if r.status_code != 200:
        print("Body:", json.dumps(r.json(), indent=2))
        return

    body = r.json()
    v = body["verdict"]

    print(f"INCIDENT:           {v['incident_short_id']}")
    print(f"OVERALL SEVERITY:   {v['overall_severity']}\n")
    print(f"EXECUTIVE SUMMARY:\n  {v['executive_summary']}\n")
    print("ATTACK NARRATIVE:")
    print("  " + v["attack_narrative"].replace("\n", "\n  "))
    print()

    print(f"TIMELINE ({len(v['timeline'])} events):")
    for i, ev in enumerate(v["timeline"], 1):
        print(f"  {i}. [{ev['timestamp'][:19]}] phase={ev['phase']}")
        print(f"     threat:  {ev['threat_short_id']}")
        if ev.get("actor"):
            print(f"     actor:   {ev['actor']}")
        if ev.get("target"):
            print(f"     target:  {ev['target']}")
        print(f"     summary: {ev['description'][:200]}")
        if ev.get("artifacts"):
            print(f"     artifacts: {ev['artifacts']}")
        print()

    if v.get("key_artifacts"):
        print(f"KEY ARTIFACTS ({len(v['key_artifacts'])}):")
        for a in v["key_artifacts"]:
            print(f"  - {a}")
        print()

    if v.get("evidence_recommendations"):
        print(f"EVIDENCE TO PRESERVE ({len(v['evidence_recommendations'])}):")
        for e in v["evidence_recommendations"]:
            print(f"  - {e}")
        print()

    if v.get("affected_assets"):
        print(f"AFFECTED ASSETS: {v['affected_assets']}")
    if v.get("affected_users"):
        print(f"AFFECTED USERS:  {v['affected_users']}")

    print()
    print(f"Run ID:  {body['run_id']}")
    print(f"Latency: {body['latency_ms']}ms")
    print(f"Tokens:  {body['total_tokens']}")


if __name__ == "__main__":
    main()