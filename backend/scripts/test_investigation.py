"""Local test script for the Investigation Agent endpoint."""
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

    print("=== Running Investigation Agent (lookback=720h to catch demo + new) ===")
    r = requests.post(
        "http://localhost:8000/api/v1/agents/investigation/correlate",
        headers={"Authorization": f"Bearer {jane_token}"},
        json={
            "lookback_hours": 720,
            "max_threats": 50,
            "min_severity": "low",
            "create_incidents": True,
        },
        timeout=60,
    )
    print(f"Status: {r.status_code}")

    if r.status_code != 200:
        print("Body:", json.dumps(r.json(), indent=2))
        return

    body = r.json()
    verdict = body["verdict"]

    print(f"\nOverall summary: {verdict['summary']}\n")
    print(f"Groups found:   {len(verdict['groups'])}")
    print(f"Unrelated:      {len(verdict['unrelated_threat_short_ids'])}")
    print(f"New incidents:  {len(body['incidents_created'])}")
    print()

    for i, g in enumerate(verdict["groups"], 1):
        print(f"--- Group {i}: {g['title']}")
        print(f"   severity={g['severity']} confidence={g['confidence']}")
        print(f"   threats:  {g['threat_short_ids']}")
        if g.get("kill_chain_phase"):
            print(f"   phase:    {g['kill_chain_phase']}")
        if g.get("attribution_hint"):
            print(f"   attrib:   {g['attribution_hint']}")
        print(f"   summary:  {g['summary'][:200]}")
        print()

    for inc in body["incidents_created"]:
        print(f"   created: {inc['short_id']} ({inc['threat_count']} threats) — {inc['title'][:80]}")

    print(f"\nRun ID:   {body['run_id']}")
    print(f"Latency:  {body['latency_ms']}ms")
    print(f"Tokens:   {body['total_tokens']}")


if __name__ == "__main__":
    main()