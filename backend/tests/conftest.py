from __future__ import annotations

import os
import time
import uuid

# Settings are read at import time; set them before anything imports `app`.
os.environ.update(
    {
        "APP_ENV": "development",
        "SUPABASE_URL": "http://localhost:54321",
        "SUPABASE_ANON_KEY": "anon-key",
        "SUPABASE_SERVICE_ROLE_KEY": "service-key",
        "SUPABASE_JWT_SECRET": "test-secret-test-secret-test-secret-123",
        "GROQ_API_KEY": "test-groq-key",
        "ABUSEIPDB_API_KEY": "",
        "DISCORD_WEBHOOK_URL": "",
        "RATE_LIMIT_ENABLED": "false",
        "LLM_RETRY_BASE_SECONDS": "0.01",
        "LOG_LEVEL": "WARNING",
        "LOG_FORMAT": "console",
    }
)

import jwt  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tests.fake_llm import FakeGroq  # noqa: E402
from tests.fake_supabase import FakeSupabase  # noqa: E402

JWT_SECRET = os.environ["SUPABASE_JWT_SECRET"]
ORG_A = "00000000-0000-0000-0000-0000000000a1"
ORG_B = "00000000-0000-0000-0000-0000000000b1"

AGENT_PROMPTS = {
    "triage": "You are the Triage Agent in ThreatBrain.",
    "investigation": "You are the Investigation Agent.",
    "response": "You are the Response Agent.",
    "threat_intel": "You are the Threat Intel Agent.",
    "forensics": "You are the Forensics Agent.",
    "compliance": "You are the Compliance Agent.",
    "hunt": "You are the Hunt Agent.",
    "log_analysis": "You are the Log Analysis Agent.",
}

USERS = {
    "owner_a": (ORG_A, "owner"),
    "admin_a": (ORG_A, "admin"),
    "analyst_a": (ORG_A, "analyst"),
    "viewer_a": (ORG_A, "viewer"),
    "owner_b": (ORG_B, "owner"),
    "analyst_b": (ORG_B, "analyst"),
}


def make_token(user_id: str, *, secret: str = JWT_SECRET, exp_in: int = 3600, aud: str = "authenticated") -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": user_id, "aud": aud, "role": "authenticated", "iat": now, "exp": now + exp_in,
         "email": f"{user_id}@example.com"},
        secret,
        algorithm="HS256",
    )


def seed(db: FakeSupabase) -> dict[str, str]:
    """Two tenants, a user of every role, agents and playbooks. Returns user ids."""
    ids: dict[str, str] = {}
    for org in (ORG_A, ORG_B):
        db.table("organizations").insert(
            {"id": org, "name": f"Org {org[-2:]}", "slug": f"org-{org[-2:]}", "plan": "free", "status": "active"}
        ).execute()
        for key, prompt in AGENT_PROMPTS.items():
            db.table("agents").insert(
                {"organization_id": org, "agent_key": key, "name": key, "model": "test-model",
                 "temperature": 0.1, "max_tokens": 1024, "system_prompt": prompt, "enabled": True}
            ).execute()
        for name, action in (("Block Malicious IP", "block_ip"), ("Disable Compromised User", "disable_user"),
                             ("Isolate Compromised Host", "isolate_host")):
            db.table("playbooks").insert(
                {"organization_id": org, "name": name, "category": action, "enabled": True,
                 "auto_execute": False, "approval_required": True, "min_confidence": 0,
                 "steps": [{"action": action}]}
            ).execute()
    for name, (org, role) in USERS.items():
        uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, name))
        ids[name] = uid
        db.table("users").insert(
            {"id": uid, "email": f"{name}@example.com", "full_name": name.replace("_", " ").title(),
             "organization_id": org, "role": role, "status": "active"}
        ).execute()
    return ids


@pytest.fixture()
def db(monkeypatch) -> FakeSupabase:
    from app.services import supabase_client

    fake = FakeSupabase()
    supabase_client.get_supabase_admin.cache_clear()
    monkeypatch.setattr(supabase_client, "create_client", lambda *a, **k: fake)
    yield fake
    supabase_client.get_supabase_admin.cache_clear()


@pytest.fixture()
def users(db) -> dict[str, str]:
    return seed(db)


@pytest.fixture()
def llm(monkeypatch) -> FakeGroq:
    from app.services import llm_service

    fake = FakeGroq()
    monkeypatch.setattr(llm_service, "_get_groq_client", lambda: fake)
    return fake


@pytest.fixture()
def client(db, users, llm) -> TestClient:
    from app.core.ratelimit import limiter
    from app.main import app

    limiter.reset()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def auth(users):
    """auth('analyst_a') -> headers for that seeded user."""

    def _headers(name: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {make_token(users[name])}"}

    return _headers
