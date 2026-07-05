"""Apply per-agent LLM model + completion-budget routing (migrations 019 & 020).

All agents run on llama-3.1-8b-instant to maximize free-tier throughput. That
model's free tier caps a single request at 6000 tokens/minute (TPM), counting
prompt + reserved max_tokens, so max_tokens is capped at 2048 — comfortably above
the largest real completion while leaving room for the prompt under the ceiling.

Idempotent — safe to re-run. Reads Supabase creds from backend/.env.

    python scripts/set_agent_models.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.supabase_client import get_supabase_admin

AGENT_MODEL = "llama-3.1-8b-instant"
AGENT_MAX_TOKENS = 2048

AGENT_KEYS = [
    "triage",
    "threat_intel",
    "investigation",
    "response",
    "forensics",
    "compliance",
    "hunt",
]


def main() -> None:
    client = get_supabase_admin()
    for agent_key in AGENT_KEYS:
        result = (
            client.table("agents")
            .update({"model": AGENT_MODEL, "max_tokens": AGENT_MAX_TOKENS})
            .eq("agent_key", agent_key)
            .execute()
        )
        print(
            f"{agent_key:14s} -> {AGENT_MODEL}  max_tokens={AGENT_MAX_TOKENS}  "
            f"({len(result.data or [])} rows)"
        )


if __name__ == "__main__":
    main()
