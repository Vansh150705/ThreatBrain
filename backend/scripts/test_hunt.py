"""Local test script for the Hunt Agent endpoint."""
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

    print("=== Generating proactive hunt hypotheses ===\n")
    r = requests.post(
        "http://localhost:8000/api/v1/agents/hunt/generate",
        headers={"Authorization": f"Bearer {jane_token}"},
        json={
            "lookback_hours": 720,
            "focus_areas": ["persistence", "lateral_movement"],
            "max_hypotheses": 5,
        },
        timeout=180,
    )
    print(f"Status: {r.status_code}\n")

    if r.status_code != 200:
        print("Body:", json.dumps(r.json(), indent=2))
        return

    body = r.json()
    v = body["verdict"]

    print(f"SUMMARY:\n  {v['summary']}\n")
    print(
        f"CONTEXT: threats={v['threats_considered']} "
        f"iocs={v['iocs_considered']} "
        f"assets={v['assets_considered']}\n"
    )

    print(f"HYPOTHESES ({len(v['hypotheses'])}):\n")
    for i, h in enumerate(v["hypotheses"], 1):
        print(f"  {i}. {h['title']}")
        print(f"     likelihood={h['likelihood']} confidence={h['confidence']}")
        print(f"     hypothesis: {h['hypothesis']}")
        if h.get("mitre_techniques"):
            print(f"     MITRE:      {h['mitre_techniques']}")
        print(f"     query:      {h['suggested_query'][:200]}")
        if h.get("expected_evidence"):
            print(f"     evidence:   {h['expected_evidence']}")
        print(f"     rationale:  {h['rationale'][:200]}")
        print()

    print(f"Run ID:  {body['run_id']}")
    print(f"Latency: {body['latency_ms']}ms")
    print(f"Tokens:  {body['total_tokens']}")


if __name__ == "__main__":
    main()