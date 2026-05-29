"""Local test script for the Compliance Agent endpoint."""
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

    target = "INC-ACT001"

    print(f"=== Assessing compliance impact of {target} ===\n")
    r = requests.post(
        "http://localhost:8000/api/v1/agents/compliance/assess",
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

    print(f"INCIDENT:                {v['incident_short_id']}")
    print(f"OVERALL COMPLIANCE RISK: {v['overall_compliance_risk']}\n")

    print(f"EXECUTIVE SUMMARY:\n  {v['executive_summary']}\n")

    if v.get("applicable_regulations"):
        print(f"APPLICABLE REGULATIONS: {v['applicable_regulations']}\n")

    if v.get("mandatory_deadlines"):
        print("MANDATORY DEADLINES:")
        for d in v["mandatory_deadlines"]:
            print(f"  ⚠️  {d}")
        print()

    print(f"REGULATION REPORTS ({len(v['reports'])}):")
    for r_report in v["reports"]:
        status_emoji = "✅" if r_report["applies"] else "⬜"
        print(f"\n  {status_emoji} {r_report['regulation']}  (applies={r_report['applies']})")
        print(f"     reason: {r_report['reason']}")
        if r_report["applies"]:
            print(f"     notification_required: {r_report['notification_required']}")
            if r_report.get("notification_deadline_hours"):
                print(f"     deadline: {r_report['notification_deadline_hours']} hours")
            if r_report.get("affected_data_categories"):
                print(f"     data categories: {r_report['affected_data_categories']}")
            if r_report.get("estimated_affected_records"):
                print(f"     estimated records: {r_report['estimated_affected_records']}")
            print(f"     risk to subjects: {r_report['risk_to_data_subjects']}")
            if r_report.get("mitigations_in_place"):
                print(f"     mitigations: {r_report['mitigations_in_place']}")
            if r_report.get("required_actions"):
                print(f"     required actions: {r_report['required_actions']}")
            if r_report.get("notification_template"):
                print(f"     template:\n       {r_report['notification_template'][:300]}")

    if v.get("recommended_next_steps"):
        print(f"\nNEXT STEPS:")
        for s in v["recommended_next_steps"]:
            print(f"  → {s}")

    print()
    print(f"Run ID:  {body['run_id']}")
    print(f"Latency: {body['latency_ms']}ms")
    print(f"Tokens:  {body['total_tokens']}")


if __name__ == "__main__":
    main()