"""LLM provider abstraction and graceful operation without a model.

The OpenAI-compatible client is exercised against a LOCAL STUB HTTP server (real sockets, real httpx), which
proves our request/response handling, retry and failure behaviour. It does NOT prove compatibility with any
specific hosted provider.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.core.config import get_settings
from app.services import llm_service
from app.services.llm_service import LLMError, LLMUnavailableError
from tests.test_pipeline import BRUTE


class Stub(BaseHTTPRequestHandler):
    script: list = []
    seen: list = []

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stub.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        status, payload = Stub.script.pop(0) if Stub.script else (200, None)
        if payload is None:
            payload = {"model": body["model"], "choices": [{"message": {"content": json.dumps({"ok": True})}}],
                       "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture()
def stub(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    Stub.script, Stub.seen = [], []
    s = get_settings()
    monkeypatch.setattr(s, "LLM_PROVIDER", "openai_compatible")
    monkeypatch.setattr(s, "LLM_BASE_URL", f"http://127.0.0.1:{srv.server_port}/v1")
    monkeypatch.setattr(s, "LLM_API_KEY", "sk-test")
    monkeypatch.setattr(s, "LLM_RETRY_BASE_SECONDS", 0.01)
    yield Stub
    srv.shutdown()


def test_compat_provider_round_trip_and_headers(stub, monkeypatch):
    monkeypatch.setattr(get_settings(), "LLM_MODEL_OVERRIDE", "my-local-model")
    data, res = llm_service.llm_json(system_prompt="s", user_prompt="u", model="llama-3.1-8b-instant")
    assert data == {"ok": True} and res.total_tokens == 18 and res.model == "my-local-model"
    seen = stub.seen[0]
    assert seen["path"] == "/v1/chat/completions" and seen["auth"] == "Bearer sk-test" and seen["body"]["model"] == "my-local-model"
    assert llm_service.llm_configured() and llm_service.provider_name() == "openai_compatible"


def test_retries_transient_errors_then_succeeds(stub):
    stub.script = [(429, {"error": "slow down"}), (503, {"error": "busy"})]
    data, _ = llm_service.llm_json(system_prompt="s", user_prompt="u")
    assert data == {"ok": True} and len(stub.seen) == 3


def test_persistent_server_error_becomes_llm_error(stub):
    stub.script = [(500, {})] * 10
    with pytest.raises(LLMError):
        llm_service.llm_json(system_prompt="s", user_prompt="u")
    assert len(stub.seen) == get_settings().LLM_MAX_RETRIES + 1     # bounded retries


def test_client_errors_are_not_retried(stub):
    stub.script = [(400, {"error": "bad request"})]
    with pytest.raises(LLMError):
        llm_service.llm_json(system_prompt="s", user_prompt="u")
    assert len(stub.seen) == 1


def test_malformed_provider_response_is_rejected_cleanly(stub):
    stub.script = [(200, {"unexpected": "shape"})]
    with pytest.raises(LLMError):
        llm_service.llm_json(system_prompt="s", user_prompt="u")


def test_plain_http_to_a_remote_host_is_refused(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "LLM_PROVIDER", "openai_compatible")
    monkeypatch.setattr(s, "LLM_BASE_URL", "http://llm.example.com/v1")
    with pytest.raises(LLMUnavailableError):
        llm_service.llm_json(system_prompt="s", user_prompt="u")


def test_provider_none_is_reported_unconfigured_and_raises(monkeypatch):
    monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "none")
    assert not llm_service.llm_configured()
    with pytest.raises(LLMUnavailableError):
        llm_service.llm_json(system_prompt="s", user_prompt="u")


# -------------------------------------------- the platform keeps working without a model
@pytest.mark.parametrize("mode", ["none", "outage"])
def test_pipeline_degrades_to_rules_only_when_the_llm_is_down(client, auth, db, llm, monkeypatch, mode):
    if mode == "none":
        monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "none")
    else:
        llm.fail_with = RuntimeError("provider outage")
    r = client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["degraded"] is True and body["summary"]["promoted_threat_id"]
    assert body["stages"]["triage"]["status"] == "degraded"
    threat = db.rows("threats")[0]
    assert threat["rule_hits"][0]["rule_id"] == "TB-AUTH-001" and "degraded-mode" in threat["tags"]
    if mode == "none":
        assert llm.calls == []                      # no model call was even attempted


def test_integrations_endpoint_reflects_the_provider(client, auth, monkeypatch):
    monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "none")
    assert client.get("/api/v1/system/integrations", headers=auth("viewer_a")).json()["llm"] is False
