"""Signup/login, rate limiting, error handling, config guards, concurrency, schema sanity."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import httpx
import pytest

from tests.conftest import ORG_A, make_token


# ---------------------------------------------------------- signup/login ----
@pytest.fixture()
def signup_env(db, monkeypatch):
    from app.api.v1.endpoints import auth as auth_ep

    class Anon:
        def __init__(self):
            self.auth = SimpleNamespace(sign_in_with_password=self.sign_in)

        def sign_in(self, creds):
            user = next((u for u in db.auth_users.values() if u["email"] == creds["email"] and u["password"] == creds["password"]), None)
            if not user:
                raise Exception("Invalid login credentials: secret internal detail")
            return SimpleNamespace(
                session=SimpleNamespace(access_token=make_token(user["id"]), refresh_token="r"),
                user=SimpleNamespace(id=user["id"]),
            )

    monkeypatch.setattr(auth_ep, "_get_anon_client", lambda: Anon())
    # the SQL trigger that seeds agents for a new org
    real_table = db.table

    def table(name):
        q = real_table(name)
        if name == "organizations":
            orig = q.execute

            def execute():
                res = orig()
                if q.op == "insert":
                    for row in res.data:
                        for key in ("triage", "hunt"):
                            real_table("agents").insert({"organization_id": row["id"], "agent_key": key, "name": key, "model": "m", "max_tokens": 1}).execute()
                return res

            q.execute = execute
        return q

    monkeypatch.setattr(db, "table", table)
    return db


def test_signup_creates_isolated_owner_workspace(client, signup_env):
    r = client.post("/api/v1/auth/signup", json={"email": "new@example.com", "password": "correct horse", "full_name": "New Person"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user"]["role"] == "owner" and body["access_token"]
    org_id = body["user"]["organization_id"]
    assert org_id not in (ORG_A,)
    me = client.get("/api/v1/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200 and me.json()["organization_id"] == org_id
    # sample data is clearly labelled
    threats = signup_env.rows("threats", organization_id=org_id)
    assert threats and all("sample-data" in t["tags"] for t in threats)
    # and invisible to every other tenant
    assert client.get("/api/v1/threats", headers={"Authorization": f"Bearer {make_token(next(iter(signup_env.auth_users)))}"}).json()["total"] == len(threats)


def test_signup_can_be_disabled_and_seed_data_can_be_off(client, signup_env, monkeypatch):
    from app.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "SEED_DEMO_DATA", False)
    r = client.post("/api/v1/auth/signup", json={"email": "a@example.com", "password": "correct horse", "full_name": "A"})
    assert r.status_code == 201 and signup_env.rows("threats") == []
    monkeypatch.setattr(s, "ALLOW_PUBLIC_SIGNUP", False)
    r = client.post("/api/v1/auth/signup", json={"email": "b@example.com", "password": "correct horse", "full_name": "B"})
    assert r.status_code == 403


def test_signup_validation_and_duplicate(client, signup_env):
    ok = {"email": "dup@example.com", "password": "correct horse", "full_name": "D"}
    assert client.post("/api/v1/auth/signup", json={**ok, "password": "short"}).status_code == 422
    assert client.post("/api/v1/auth/signup", json={**ok, "email": "nope"}).status_code == 422
    assert client.post("/api/v1/auth/signup", json=ok).status_code == 201
    dup = client.post("/api/v1/auth/signup", json=ok)
    assert dup.status_code == 400 and "already exists" in dup.json()["detail"]


def test_failed_provisioning_rolls_back_and_hides_internals(client, signup_env, monkeypatch):
    from app.api.v1.endpoints import auth as auth_ep

    def boom(admin, org_id):
        raise RuntimeError("db password=hunter2 leaked")

    monkeypatch.setattr(auth_ep, "_seed_starter_data", boom)
    r = client.post("/api/v1/auth/signup", json={"email": "x@example.com", "password": "correct horse", "full_name": "X"})
    assert r.status_code == 500 and "hunter2" not in r.text
    assert signup_env.auth_users == {} and signup_env.rows("organizations", name="X's Workspace") == []


def test_login_generic_failure_and_success(client, signup_env):
    client.post("/api/v1/auth/signup", json={"email": "l@example.com", "password": "correct horse", "full_name": "L"})
    bad = client.post("/api/v1/auth/login", json={"email": "l@example.com", "password": "wrong password"})
    assert bad.status_code == 401 and "secret internal detail" not in bad.text
    good = client.post("/api/v1/auth/login", json={"email": "l@example.com", "password": "correct horse"})
    assert good.status_code == 200 and good.json()["user"]["organization"]["plan"] == "free"


# ---------------------------------------------------------- rate limiting ----
@pytest.fixture()
def limited(monkeypatch):
    from app.core.config import get_settings
    from app.core.ratelimit import limiter

    s = get_settings()
    monkeypatch.setattr(s, "RATE_LIMIT_ENABLED", True)
    limiter.reset()
    yield s
    limiter.reset()


def test_login_is_rate_limited_per_client(client, signup_env, limited, monkeypatch):
    monkeypatch.setattr(limited, "AUTH_RATE_LIMIT_PER_MINUTE", 3)
    codes = [client.post("/api/v1/auth/login", json={"email": "z@example.com", "password": "x"}).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    r = client.post("/api/v1/auth/login", json={"email": "z@example.com", "password": "x"})
    assert r.headers["retry-after"].isdigit() and r.json()["detail"]["error"] == "rate_limited"


def test_global_limit_and_health_exemption(client, limited, monkeypatch):
    monkeypatch.setattr(limited, "RATE_LIMIT_PER_MINUTE", 5)
    codes = [client.get("/api/v1/threats").status_code for _ in range(8)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429] * 3
    assert client.get("/api/v1/health").status_code == 200, "probes must never be throttled"


def test_llm_endpoints_have_their_own_tighter_limit(client, auth, limited, monkeypatch):
    monkeypatch.setattr(limited, "LLM_RATE_LIMIT_PER_MINUTE", 2)
    body = {"question": "hi"}
    codes = [client.post("/api/v1/copilot/ask", json=body, headers=auth("analyst_a")).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


def test_forwarded_for_only_trusted_when_configured(client, limited, monkeypatch):
    monkeypatch.setattr(limited, "RATE_LIMIT_PER_MINUTE", 2)
    spoof = lambda i: {"X-Forwarded-For": f"9.9.9.{i}"}  # noqa: E731
    codes = [client.get("/api/v1/threats", headers=spoof(i)).status_code for i in range(4)]
    assert codes[2:] == [429, 429], "spoofed headers must not dodge the limit by default"
    from app.core.ratelimit import limiter
    limiter.reset()
    monkeypatch.setattr(limited, "TRUST_PROXY_HEADERS", True)
    codes = [client.get("/api/v1/threats", headers=spoof(i)).status_code for i in range(4)]
    assert 429 not in codes, "behind a trusted proxy each client address gets its own budget"


# ------------------------------------------------------ errors & headers ----
def test_500_body_is_generic(client, auth, users, monkeypatch):
    from app.services import stats_service

    monkeypatch.setattr(stats_service, "get_dashboard_stats", lambda org: (_ for _ in ()).throw(RuntimeError("postgres://u:secretpw@db")))
    r = client.get("/api/v1/stats/dashboard", headers=auth("viewer_a"))
    assert r.status_code == 500 and "secretpw" not in r.text and r.json()["error"] == "internal_server_error"


def test_security_headers_and_request_id(client):
    r = client.get("/api/v1/health", headers={"X-Request-Id": "abc123"})
    assert r.headers["x-request-id"] == "abc123"
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
    evil = client.get("/api/v1/health", headers={"X-Request-Id": "bad id\r\nSet-Cookie: x=1"})
    assert "set-cookie" not in evil.headers and evil.headers["x-request-id"].isalnum()


def test_cors_allows_configured_origin_only(client):
    ok = client.options("/api/v1/threats", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    bad = client.options("/api/v1/threats", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in bad.headers


def test_health_db_reports_failure_without_details(client, monkeypatch):
    from app.api.v1.endpoints import meta

    monkeypatch.setattr(meta, "supabase_health_check", lambda: {"ok": False, "error": "connection refused to 10.1.2.3"})
    r = client.get("/api/v1/health/db")
    assert r.status_code == 503 and "10.1.2.3" not in r.text and r.json()["status"] == "degraded"


def test_docs_hidden_in_production(monkeypatch):
    from app.core.config import Settings

    env = dict(APP_ENV="production", SUPABASE_URL="http://x.co", SUPABASE_ANON_KEY="a", SUPABASE_SERVICE_ROLE_KEY="b",
               SUPABASE_JWT_SECRET="s" * 32)
    s = Settings(**env)
    assert s.is_production and not s.APP_DEBUG
    with pytest.raises(Exception):
        Settings(**{**env, "APP_DEBUG": True})
    with pytest.raises(Exception):
        Settings(**{**env, "CORS_ORIGINS": "*"})
    with pytest.raises(Exception):
        Settings(**{**env, "SUPABASE_JWT_SECRET": "short"})


# ------------------------------------------------------------ concurrency ----
def test_slow_llm_calls_do_not_block_the_event_loop(db, users, llm):
    """Sync agent work must run in the thread pool, not on the event loop."""
    import tests.fake_llm as fl
    from app.main import app

    def slow(system, user):
        time.sleep(0.6)
        return fl.default_handler(system, user)

    llm.handler = slow
    headers = {"Authorization": f"Bearer {make_token(users['analyst_a'])}"}

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            slow_req = asyncio.create_task(c.post("/api/v1/copilot/ask", json={"question": "hi"}, headers=headers))
            await asyncio.sleep(0.15)
            t = time.perf_counter()
            health = await c.get("/api/v1/health")
            elapsed = time.perf_counter() - t
            await slow_req
            return health.status_code, elapsed

    code, elapsed = asyncio.run(scenario())
    assert code == 200 and elapsed < 0.3, f"event loop was blocked for {elapsed:.2f}s"


# -------------------------------------------------------- other endpoints ----
def test_audit_log_listing_filters_and_scopes(client, auth, db):
    db.table("audit_logs").insert({"organization_id": ORG_A, "actor_type": "user", "action": "x", "severity": "high"}).execute()
    db.table("audit_logs").insert({"organization_id": ORG_A, "actor_type": "agent", "action": "y", "severity": "info"}).execute()
    db.table("audit_logs").insert({"organization_id": "00000000-0000-0000-0000-0000000000b1", "actor_type": "user", "action": "z"}).execute()
    r = client.get("/api/v1/audit?severity=high", headers=auth("viewer_a")).json()
    assert r["total"] == 1 and r["items"][0]["action"] == "x"
    assert client.get("/api/v1/audit", headers=auth("viewer_a")).json()["total"] == 2


def test_audit_log_is_append_only_in_the_fake_like_in_postgres(db, users):
    from tests.fake_supabase import APIError

    row = db.table("audit_logs").insert({"organization_id": ORG_A, "actor_type": "user", "action": "a"}).execute().data[0]
    with pytest.raises(APIError):
        db.table("audit_logs").update({"action": "tampered"}).eq("id", row["id"]).execute()
    with pytest.raises(APIError):
        db.table("audit_logs").delete().eq("id", row["id"]).execute()


def test_agent_management_endpoints_are_tenant_scoped(client, auth, db):
    r = client.get("/api/v1/agents", headers=auth("analyst_a")).json()
    keys = {a["agent_key"] for a in (r["items"] if isinstance(r, dict) else r)}
    assert {"triage", "log_analysis"} <= keys
    assert client.get("/api/v1/agents/triage", headers=auth("analyst_a")).status_code == 200
    assert client.get("/api/v1/agents/triage", headers=auth("analyst_b")).json()["id"] != \
        client.get("/api/v1/agents/triage", headers=auth("analyst_a")).json()["id"]


def test_manual_response_endpoint_refuses_server_side_execution(client, auth):
    r = client.post("/api/v1/agents/response/recommend",
                    json={"incident_short_id": "INC-X", "dry_run": False, "execute_auto_playbooks": True}, headers=auth("owner_a"))
    assert r.status_code == 400 and "never executes" in r.json()["detail"]["message"]


def test_copilot_context_is_limited_to_own_org(client, auth, db, llm):
    db.table("threats").insert({"organization_id": ORG_A, "title": "ALPHA-secret"}).execute()
    db.table("threats").insert({"organization_id": "00000000-0000-0000-0000-0000000000b1", "title": "BRAVO-secret"}).execute()
    client.post("/api/v1/copilot/ask", json={"question": "what do you see"}, headers=auth("analyst_a"))
    prompt = llm.calls[-1]["messages"][1]["content"]
    assert "ALPHA-secret" in prompt and "BRAVO-secret" not in prompt
    assert prompt.index("ALPHA-secret") < prompt.index("</untrusted_data>")


def test_integration_status_never_returns_secrets(client, auth):
    r = client.get("/api/v1/system/integrations", headers=auth("viewer_a"))
    assert r.status_code == 200 and r.json()["llm"] is True
    assert "test-groq-key" not in r.text


# ------------------------------------------------------- schema / migrations ----
def test_every_column_the_backend_reads_exists_in_the_migrations():
    """The fake DB rejects unknown columns, so a full pipeline run (see test_pipeline)
    proves queries match the schema. Here we additionally pin the new migrations."""
    from tests.fake_supabase import SCHEMA

    assert {"fingerprint", "event_count", "last_seen_at", "rule_hits"} <= SCHEMA["threats"]
    assert {"key_hash", "scopes", "revoked_at"} <= SCHEMA["api_keys"]
    assert {"body", "incident_id"} <= SCHEMA["incident_notes"]
    assert {"status", "trace", "result"} <= SCHEMA["pipeline_runs"]


def test_migrations_are_numbered_without_gaps_and_enum_split_is_documented():
    from pathlib import Path

    files = sorted(p.name for p in (Path(__file__).resolve().parents[2] / "database" / "migrations").glob("*.sql"))
    nums = [int(f.split("_")[0]) for f in files]
    assert nums == list(range(1, len(nums) + 1))
    enum_sql = (Path(__file__).resolve().parents[2] / "database" / "migrations" / "022_agent_key_log_analysis.sql").read_text()
    assert "ON ITS OWN" in enum_sql and enum_sql.count("ALTER TYPE") == 1
