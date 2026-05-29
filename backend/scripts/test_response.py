"""Local test script for the Response Agent endpoint."""
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


def call(token: str, *, incident_short_id: str, dry_run: bool, exec_auto: bool) -> dict:
    r = requests.post(
        "http://localhost:8000/api/v1/agents/response/recommend",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "incident_short_id": incident_short_id,
            "dry_run": dry_run,
            "execute_auto_playbooks": exec_auto,
        },
        timeout=60,
    )
    return {"status": r.status_code, "body": r.json()}


def print_result(label: str, result: dict) -> None:
    print(f"=== {label} ===")
    print(f"Status: {result['status']}")
    if result["status"] != 200:
        print("Body:", json.dumps(result["body"], indent=2))
        return
    body = result["body"]
    v = body["verdict"]
    print(f"Incident:  {v['incident_short_id']}  severity={v['overall_severity']}")
    print(f"Summary:   {v['summary']}")
    print(
        f"Counts:    executed={v['executed_count']} "
        f"simulated={v['simulated_count']} "
        f"recommended={v['recommended_count']} "
        f"skipped={v['skipped_count']}"
    )
    print()
    for i, a in enumerate(v["actions"], 1):
        print(f"  {i}. [{a['status']}] {a['action_type']} → {a['target']}")
        print(f"     playbook: {a['playbook_name']}  priority={a['priority']}")
        print(f"     why:      {a['rationale'][:200]}")
    print()
    print(f"Run ID:  {body['run_id']}  Latency: {body['latency_ms']}ms  Tokens: {body['total_tokens']}")
    print()


def main() -> None:
    settings = get_settings()
    jane_token = make_token(
        "00000000-0000-0000-0000-00000000a001",
        "jane.morrison@acme.example",
        secret=settings.SUPABASE_JWT_SECRET,
    )

    target = "INC-ACT001"  # change to a real INC-* short_id from your DB

    # Test 1: dry run — everyone is allowed
    print_result(
        f"Dry run on {target}",
        call(jane_token, incident_short_id=target, dry_run=True, exec_auto=False),
    )

    # Test 2: recommend-only mode (no execution even when not dry-run)
    print_result(
        f"Recommend only on {target}",
        call(jane_token, incident_short_id=target, dry_run=False, exec_auto=False),
    )


if __name__ == "__main__":
    main()