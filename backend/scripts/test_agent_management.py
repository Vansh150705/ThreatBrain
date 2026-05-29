"""Local test script for the agent management endpoints."""
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
    token = make_token(
        "00000000-0000-0000-0000-00000000a001",
        "jane.morrison@acme.example",
        secret=settings.SUPABASE_JWT_SECRET,
    )
    headers = {"Authorization": f"Bearer {token}"}
    base = "http://localhost:8000/api/v1/agents"

    print("=" * 60)
    print("1. List all agents")
    print("=" * 60)
    r = requests.get(base, headers=headers, timeout=30)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        body = r.json()
        print(f"Total agents: {body['total']}")
        for a in body["items"]:
            print(
                f"  • {a['agent_key']:<14} "
                f"status={a['status']} "
                f"enabled={a['enabled']} "
                f"runs={a['total_runs']} "
                f"avg_latency={a.get('avg_latency_ms')}ms"
            )
    print()

    print("=" * 60)
    print("2. Get one agent (triage)")
    print("=" * 60)
    r = requests.get(f"{base}/triage", headers=headers, timeout=30)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        a = r.json()
        print(f"Name:        {a['name']}")
        print(f"Description: {a.get('description', '')[:120]}")
        print(f"Model:       {a.get('model')}  temp={a.get('temperature')}")
        print(f"Stats:       {a['total_runs']} runs ({a['successful_runs']} ok / {a['failed_runs']} failed)")
    print()

    print("=" * 60)
    print("3. List recent runs across ALL agents")
    print("=" * 60)
    r = requests.get(
        f"{base}/recent-runs?page_size=10", headers=headers, timeout=30
    )
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        body = r.json()
        print(f"Total runs: {body['pagination']['total']}")
        for run in body["items"][:10]:
            print(
                f"  • {run['agent_key']:<14} "
                f"{run['status']:<10} "
                f"latency={run.get('latency_ms')}ms "
                f"tokens={run.get('total_tokens')}"
            )
    print()

    print("=" * 60)
    print("4. List recent runs for triage agent only")
    print("=" * 60)
    r = requests.get(f"{base}/triage/runs?page_size=5", headers=headers, timeout=30)
    print(f"Status: {r.status_code}")
    if r.status_code == 200:
        body = r.json()
        print(f"Total triage runs: {body['pagination']['total']}")
        for run in body["items"][:5]:
            print(
                f"  • {run['id'][:8]}... "
                f"{run['status']:<10} "
                f"trigger={run['trigger_type']:<10} "
                f"tokens={run.get('total_tokens')}"
            )
        if body["items"]:
            sample_run_id = body["items"][0]["id"]

            print()
            print("=" * 60)
            print(f"5. Get full details of run {sample_run_id[:8]}...")
            print("=" * 60)
            r = requests.get(
                f"{base}/runs/{sample_run_id}", headers=headers, timeout=30
            )
            print(f"Status: {r.status_code}")
            if r.status_code == 200:
                run = r.json()
                print(f"Agent:       {run['agent_key']}")
                print(f"Status:      {run['status']}")
                print(f"Model:       {run['model']}")
                print(f"Tokens:      p={run['prompt_tokens']} c={run['completion_tokens']} total={run['total_tokens']}")
                print(f"Latency:     {run['latency_ms']}ms")
                output_preview = json.dumps(run.get("output", {}), indent=2)[:400]
                print(f"\nOutput preview:\n{output_preview}")


if __name__ == "__main__":
    main()