"""Local test script for the Threat Intel Agent endpoint."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add the backend root (parent of scripts/) to sys.path so `app.*` imports work
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


def enrich(ip: str, token: str, context: str | None = None) -> None:
    print(f"=== Enriching IP: {ip} ===")
    payload: dict = {"ip_address": ip}
    if context:
        payload["context"] = context

    r = requests.post(
        "http://localhost:8000/api/v1/agents/threat-intel/enrich",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
        timeout=60,
    )
    print(f"Status: {r.status_code}")

    if r.status_code != 200:
        print("Body:", json.dumps(r.json(), indent=2))
        print()
        return

    body = r.json()
    v = body["verdict"]
    print(f"Reputation:    {v['reputation']}")
    print(f"Severity:      {v['severity']}")
    print(f"Confidence:    {v['confidence']}")
    print(f"Threat Score:  {v['threat_score']}")
    print(f"Country:       {v.get('country_code')}")
    print(f"ISP:           {v.get('isp')}")
    print(f"AbuseScore:    {v.get('abuse_score')} / 100")
    print(f"Total Reports: {v.get('total_reports')}")
    print(f"Tags:          {v.get('tags')}")
    print(f"Summary:       {v['summary']}")
    print()
    print(f"Run ID:        {body['run_id']}")
    print(f"Latency:       {body['latency_ms']}ms")
    print(f"Tokens:        {body['total_tokens']}")
    print()


def main() -> None:
    settings = get_settings()
    jane_token = make_token(
        "00000000-0000-0000-0000-00000000a001",
        "jane.morrison@acme.example",
        secret=settings.SUPABASE_JWT_SECRET,
    )

    # Test 1 — Cloudflare DNS (clean IP, should be benign)
    enrich(
        "1.1.1.1",
        jane_token,
        context="Outbound DNS query from prod-web-01.",
    )

    # Test 2 — A well-known malicious IP. Most threat researchers report
    # this range. If yours comes back clean, that's also a useful signal.
    enrich(
        "185.220.101.1",
        jane_token,
        context="Inbound connection seen in firewall logs on edge-firewall-01.",
    )


if __name__ == "__main__":
    main()