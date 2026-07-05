"""Apply the per-agent LLM model routing (migration 018).

Groq's daily token limit is enforced per model, so splitting the pipeline
across two models spreads the load across separate quota buckets. Deterministic
/ low-stakes agents run on the faster llama-3.1-8b-instant; reasoning-heavy
agents stay on llama-3.3-70b-versatile.

Idempotent — safe to re-run. Reads Supabase creds from backend/.env.

    python scripts/set_agent_models.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.supabase_client import get_supabase_admin

# agent_key -> model. Keep this in sync with database/migrations/018_route_agent_models.sql
AGENT_MODELS: dict[str, str] = {
    "triage": "llama-3.3-70b-versatile",
    "threat_intel": "llama-3.1-8b-instant",
    "investigation": "llama-3.3-70b-versatile",
    "response": "llama-3.3-70b-versatile",
    "forensics": "llama-3.3-70b-versatile",
    "compliance": "llama-3.3-70b-versatile",
    "hunt": "llama-3.1-8b-instant",
}


def main() -> None:
    client = get_supabase_admin()
    for agent_key, model in AGENT_MODELS.items():
        result = (
            client.table("agents")
            .update({"model": model})
            .eq("agent_key", agent_key)
            .execute()
        )
        print(f"{agent_key:14s} -> {model:24s} ({len(result.data or [])} rows)")


if __name__ == "__main__":
    main()
