"""Groq retired llama-3.1-8b-instant and llama-3.3-70b-versatile (the API answers 404). Older agent rows and seed functions
still name them, so the Groq path must map them to current models instead of failing every agent."""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from app.core.config import get_settings
from app.services import llm_service


@pytest.fixture()
def seen(monkeypatch):
    calls: list[dict] = []

    def create(**kw):
        calls.append(kw)
        return NS(
            choices=[NS(message=NS(content='{"ok": true}'))],
            model=kw["model"],
            usage=NS(prompt_tokens=1, completion_tokens=1, total_tokens=2),
        )

    client = NS(chat=NS(completions=NS(create=create)))
    monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "groq")
    monkeypatch.setattr(llm_service, "_get_groq_client", lambda: client)
    return calls


@pytest.mark.parametrize(
    ("asked", "served"),
    [
        ("llama-3.1-8b-instant", "openai/gpt-oss-20b"),
        ("llama-3.3-70b-versatile", "openai/gpt-oss-120b"),
    ],
)
def test_retired_models_are_mapped_to_their_successors(seen, asked, served):
    data, res = llm_service.llm_json(system_prompt="s", user_prompt="u", model=asked)
    assert data == {"ok": True} and res.model == served
    assert seen[0]["model"] == served


def test_current_models_pass_through_untouched(seen):
    llm_service.llm_json(system_prompt="s", user_prompt="u", model="qwen/qwen3.8-27b")
    assert seen[0]["model"] == "qwen/qwen3.8-27b"
    assert "extra_body" not in seen[0]


def test_reasoning_models_are_asked_for_low_effort(seen):
    llm_service.llm_json(system_prompt="s", user_prompt="u", model="llama-3.1-8b-instant")
    assert seen[0]["extra_body"] == {"reasoning_effort": "low"}
    assert seen[0]["response_format"] == {"type": "json_object"}


def test_default_model_is_not_a_retired_one():
    # The code default, not the live setting: a developer's own .env may still name an old model (the alias covers that).
    from app.core.config import Settings

    assert Settings.model_fields["GROQ_MODEL"].default not in llm_service.RETIRED_GROQ_MODELS


def test_openai_compatible_endpoints_keep_the_operators_model_names(monkeypatch):
    """A self-hosted server may legitimately serve a model called llama-3.1-8b-instant; do not rewrite it there."""
    assert llm_service._groq_kwargs({"model": "my-local-model"})["model"] == "my-local-model"
    sent: list[dict] = []

    class Compat:
        chat = NS(completions=NS(create=lambda **kw: (sent.append(kw), NS(choices=[NS(message=NS(content="{}"))], model=kw["model"], usage=None))[1]))

    monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "openai_compatible")
    monkeypatch.setattr(llm_service, "_compat_client", lambda: Compat())
    llm_service.llm_json(system_prompt="s", user_prompt="u", model="llama-3.1-8b-instant")
    assert sent[0]["model"] == "llama-3.1-8b-instant"


# ------------------------------------------------------------------------------- rate limits (429 + Retry-After)
def _rate_limit(retry_after: str | None):
    import httpx
    from groq import RateLimitError

    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return RateLimitError("rate limited", response=httpx.Response(429, headers=headers, request=httpx.Request("POST", "http://x")), body=None)


def _state(exc):
    return NS(outcome=NS(failed=True, exception=lambda: exc))


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [
        ("9", 9.5),        # the provider says when the bucket refills: wait that long (plus a little)
        ("0", 1.0),        # never shorter than the normal backoff
        ("3600", 20.0),    # a daily-quota 429 must not hold a pipeline stage open for an hour
        (None, 1.0),       # no header: normal backoff
        ("soon", 1.0),     # unparsable header: normal backoff
    ],
)
def test_wait_follows_retry_after_within_bounds(retry_after, expected):
    wait = llm_service._wait_honoring_retry_after(lambda state: 1.0)
    assert wait(_state(_rate_limit(retry_after))) == expected


def test_other_errors_keep_the_plain_backoff():
    wait = llm_service._wait_honoring_retry_after(lambda state: 2.0)
    assert wait(_state(ValueError("boom"))) == 2.0


def test_a_rate_limited_call_is_retried_until_it_succeeds(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(settings, "LLM_MAX_RETRIES", 2)
    monkeypatch.setattr(settings, "LLM_RETRY_BASE_SECONDS", 0.01)
    monkeypatch.setattr(llm_service, "MAX_RATE_LIMIT_WAIT_SECONDS", 0.05)
    attempts = []

    def create(**kw):
        attempts.append(kw["model"])
        if len(attempts) < 3:
            raise _rate_limit("1")
        return NS(choices=[NS(message=NS(content='{"ok": true}'))], model=kw["model"], usage=NS(prompt_tokens=1, completion_tokens=1, total_tokens=2))

    monkeypatch.setattr(llm_service, "_get_groq_client", lambda: NS(chat=NS(completions=NS(create=create))))
    data, _ = llm_service.llm_json(system_prompt="s", user_prompt="u", model="openai/gpt-oss-20b")
    assert data == {"ok": True} and len(attempts) == 3
