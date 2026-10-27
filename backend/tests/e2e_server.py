"""Boot the real FastAPI app on an in-memory database with a scripted LLM.

Used for browser end-to-end checks without Supabase or Groq credentials:

    python -m tests.e2e_server --port 8001

Prints a JSON blob with ready-made JWTs for the seeded users. This is a test
rig, not a production mode: data lives in memory and the "LLM" is canned.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# conftest sets the environment (must happen before app import)
import tests.conftest as c  # noqa: F401  (side effect: env vars)

os.environ["CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173"
os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["LLM_RETRY_BASE_SECONDS"] = "0.01"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    import uvicorn

    from app.services import llm_service, supabase_client
    from tests.fake_llm import FakeGroq
    from tests.fake_supabase import FakeSupabase

    db = FakeSupabase()
    supabase_client.get_supabase_admin.cache_clear()
    supabase_client.create_client = lambda *a, **k: db  # type: ignore[assignment]
    llm_service._get_groq_client = lambda: FakeGroq()  # type: ignore[assignment]
    users = c.seed(db)

    from app.agents.triage import TriageInput
    from app.services import pipeline_service

    for ev in (
        dict(title="SSH brute-force from 203.0.113.42", description="25 failed ssh logins in 60s",
             event_type="authentication.brute_force", source_ip="203.0.113.42", username="root", asset_name="web-01"),
        dict(title="Shadow copies deleted", event_type="endpoint.process", source_ip="198.51.100.77",
             command_line="vssadmin.exe delete shadows /all /quiet", asset_name="fs-01", asset_criticality="high"),
        dict(title="CloudTrail logging stopped", event_type="cloud.cloudtrail.StopLogging", source_ip="198.51.100.9",
             raw_data={"eventName": "StopLogging", "userIdentity": {"type": "IAMUser", "userName": "eve"}}),
    ):
        pipeline_service.run_sync(c.ORG_A, TriageInput(**ev), source="seed", created_by="seed")

    tokens = {name: c.make_token(uid, exp_in=86400) for name, uid in users.items()}
    print(json.dumps({"users": users, "tokens": tokens}), flush=True)
    sys.stdout.flush()

    from app.main import app

    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
