"""Local test script for the Triage Agent endpoint."""
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


def main() -> None:
    settings = get_settings()
    jane_token = make_token(
        "00000000-0000-0000-0000-00000000a001",
        "jane.morrison@acme.example",
        secret=settings.SUPABASE_JWT_SECRET,
    )

    print("=== Test 1: High-severity SSH brute-force event ===")
    payload = {
        "event": {
            "title": "Multiple failed SSH logins from RU botnet IP",
            "description": (
                "47 failed login attempts in 3 minutes targeting root, "
                "admin, ubuntu, postgres on prod-web-01."
            ),
            "source": "authentication",
            "event_type": "authentication.failed",
            "source_ip": "203.0.113.42",
            "destination_ip": "10.0.1.10",
            "destination_port": 22,
            "username": "root",
            "asset_name": "prod-web-01",
            "asset_type": "server",
            "asset_environment": "production",
            "asset_criticality": "high",
        },
        "promote_if_recommended": True,
        "primary_asset_id": "00000000-0000-0000-0000-00000000b001",
    }

    r = requests.post(
        "http://localhost:8000/api/v1/agents/triage/classify",
        headers={"Authorization": f"Bearer {jane_token}"},
        json=payload,
        timeout=60,
    )
    print(f"Status: {r.status_code}")
    body = r.json()

    if r.status_code != 200:
        print("Body:", json.dumps(body, indent=2))
        return

    print("Verdict:")
    print(json.dumps(body["verdict"], indent=2))
    print()
    print(f"Run ID:               {body['run_id']}")
    print(f"Model:                {body['model']}")
    print(f"Latency:              {body['latency_ms']}ms")
    print(f"Tokens:               {body['total_tokens']}")
    print(f"Promoted threat ID:   {body['promoted_threat_id']}")


if __name__ == "__main__":
    main()