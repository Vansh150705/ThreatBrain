"""Local test script for the Orchestrator endpoint."""
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

    payload = {
        "event": {
            "title": "Suspicious SSH activity from Russian botnet IP",
            "description": (
                "Burst of failed SSH logins followed by a successful "
                "login to ubuntu account on prod-web-01, then a wget "
                "of a suspicious script."
            ),
            "source": "authentication",
            "event_type": "authentication.failed",
            "source_ip": "203.0.113.42",
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "username": "ubuntu",
            "asset_name": "prod-web-01",
            "asset_type": "server",
            "asset_environment": "production",
            "asset_criticality": "high",
        },
        "promote_threats": True,
        "primary_asset_id": "00000000-0000-0000-0000-00000000b001",
        "investigation_lookback_hours": 720,
    }

    print("=== Running full agent pipeline ===\n")
    print("⚠️  This calls 5-6 LLM agents in sequence. Expect 10-25 seconds.\n")

    t0 = time.perf_counter()
    r = requests.post(
        "http://localhost:8000/api/v1/orchestrator/handle-event",
        headers={"Authorization": f"Bearer {jane_token}"},
        json=payload,
        timeout=300,
    )
    wall_clock_ms = int((time.perf_counter() - t0) * 1000)

    print(f"Status: {r.status_code}")
    print(f"Wall clock: {wall_clock_ms}ms\n")

    if r.status_code != 200:
        print("Body:", json.dumps(r.json(), indent=2))
        return

    body = r.json()
    stages = body["stages"]
    summary = body["summary"]

    print("─" * 60)
    print("PIPELINE SUMMARY")
    print("─" * 60)
    print(f"  Stages run:       {summary['stages_run']}")
    print(f"  Stages succeeded: {summary['stages_succeeded']}")
    print(f"  Stages failed:    {summary['stages_failed']}")
    print(f"  Stages skipped:   {summary['stages_skipped']}")
    print(f"  Threat promoted:  {summary.get('promoted_threat_id') or '—'}")
    print(f"  Incident:         {summary.get('incident_short_id') or '—'}")
    print()

    for name in (
        "triage",
        "threat_intel",
        "investigation",
        "response",
        "forensics",
        "compliance",
    ):
        s = stages.get(name, {})
        st = s.get("status", "?")
        icon = {"ok": "✅", "failed": "❌", "skipped": "⬜"}.get(st, "?")
        print(f"  {icon} {name:<14} status={st}")
        if st == "ok":
            print(
                f"     run_id={s.get('run_id', '?')[:8]}...  "
                f"latency={s.get('latency_ms')}ms  tokens={s.get('tokens')}"
            )
        elif st == "failed":
            print(f"     error: {s.get('error', '?')[:200]}")
        else:
            print(f"     reason: {s.get('reason', '?')}")
        print()

    # Optional: pretty-print one verdict to show the data is there
    if stages.get("triage", {}).get("status") == "ok":
        v = stages["triage"]["verdict"]
        print("─" * 60)
        print("TRIAGE VERDICT (sample)")
        print("─" * 60)
        print(f"  severity:    {v.get('severity')}")
        print(f"  confidence:  {v.get('confidence')}")
        print(f"  mitre:       {v.get('mitre_techniques')}")
        print(f"  title:       {v.get('title')}")


if __name__ == "__main__":
    main()