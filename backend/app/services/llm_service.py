from __future__ import annotations

import json
import time
from typing import Any

from groq import Groq, APIError, RateLimitError
from groq.types.chat import ChatCompletion
from langchain_groq import ChatGroq
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


_groq_client: Groq | None = None
_langchain_client: ChatGroq | None = None


def _get_groq_client() -> Groq:
    """Lazily build the raw Groq SDK client."""
    global _groq_client
    if _groq_client is None:
        settings = get_settings()
        if not settings.GROQ_API_KEY:
            raise RuntimeError(
                "GROQ_API_KEY is not configured. Set it in backend/.env."
            )
        _groq_client = Groq(api_key=settings.GROQ_API_KEY)
        log.info("groq_client_initialized", model=settings.GROQ_MODEL)
    return _groq_client


def get_langchain_chat(
    *,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> ChatGroq:

    settings = get_settings()
    return ChatGroq(
        api_key=settings.GROQ_API_KEY,
        model=model or settings.GROQ_MODEL,
        temperature=temperature if temperature is not None else settings.GROQ_TEMPERATURE,
        max_tokens=max_tokens or settings.GROQ_MAX_TOKENS,
    )

class LLMResult:

    def __init__(
        self,
        *,
        content: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        latency_ms: int,
        raw: ChatCompletion,
    ) -> None:
        self.content = content
        self.model = model
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens
        self.latency_ms = latency_ms
        self.raw = raw

    def as_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "latency_ms": self.latency_ms,
        }


class LLMError(Exception):
    """Raised when an LLM call fails after retries."""

_retry_decorator = retry(
    retry=retry_if_exception_type((RateLimitError, APIError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)


def llm_complete(
    *,
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> LLMResult:

    settings = get_settings()
    chosen_model = model or settings.GROQ_MODEL
    chosen_temp = temperature if temperature is not None else settings.GROQ_TEMPERATURE
    chosen_max_tokens = max_tokens or settings.GROQ_MAX_TOKENS

    @_retry_decorator
    def _call() -> ChatCompletion:
        return _get_groq_client().chat.completions.create(
            model=chosen_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=chosen_temp,
            max_tokens=chosen_max_tokens,
        )

    start = time.perf_counter()
    try:
        response = _call()
    except Exception as exc:
        log.exception(
            "llm_call_failed",
            model=chosen_model,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )
        raise LLMError(f"LLM call failed: {exc}") from exc

    latency_ms = int((time.perf_counter() - start) * 1000)
    content = response.choices[0].message.content or ""
    usage = response.usage

    result = LLMResult(
        content=content,
        model=response.model,
        prompt_tokens=usage.prompt_tokens if usage else 0,
        completion_tokens=usage.completion_tokens if usage else 0,
        total_tokens=usage.total_tokens if usage else 0,
        latency_ms=latency_ms,
        raw=response,
    )

    log.info(
        "llm_call_completed",
        model=result.model,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        total_tokens=result.total_tokens,
        latency_ms=result.latency_ms,
        temperature=chosen_temp,
    )
    return result

def llm_json(
    *,
    system_prompt: str,
    user_prompt: str,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
) -> tuple[dict[str, Any], LLMResult]:

    settings = get_settings()
    chosen_model = model or settings.GROQ_MODEL
    chosen_temp = temperature if temperature is not None else settings.GROQ_TEMPERATURE
    chosen_max_tokens = max_tokens or settings.GROQ_MAX_TOKENS

    json_system = system_prompt.rstrip() + (
        "\n\nIMPORTANT: respond with a single valid JSON object. "
        "No prose, no markdown fences, just JSON."
    )

    @_retry_decorator
    def _call() -> ChatCompletion:
        return _get_groq_client().chat.completions.create(
            model=chosen_model,
            messages=[
                {"role": "system", "content": json_system},
                {"role": "user", "content": user_prompt},
            ],
            temperature=chosen_temp,
            max_tokens=chosen_max_tokens,
            response_format={"type": "json_object"},
        )

    start = time.perf_counter()
    try:
        response = _call()
    except Exception as exc:
        log.exception("llm_json_call_failed", model=chosen_model)
        raise LLMError(f"LLM JSON call failed: {exc}") from exc

    latency_ms = int((time.perf_counter() - start) * 1000)
    content = response.choices[0].message.content or "{}"
    usage = response.usage

    result = LLMResult(
        content=content,
        model=response.model,
        prompt_tokens=usage.prompt_tokens if usage else 0,
        completion_tokens=usage.completion_tokens if usage else 0,
        total_tokens=usage.total_tokens if usage else 0,
        latency_ms=latency_ms,
        raw=response,
    )

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        log.error(
            "llm_json_parse_failed",
            content_preview=content[:200],
            error=str(exc),
        )
        raise LLMError(f"LLM returned invalid JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise LLMError(
            f"LLM returned JSON that wasn't an object: {type(parsed).__name__}"
        )

    log.info(
        "llm_json_call_completed",
        model=result.model,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        total_tokens=result.total_tokens,
        latency_ms=result.latency_ms,
        json_keys=list(parsed.keys()),
    )

    return parsed, result


__all__ = [
    "LLMResult",
    "LLMError",
    "llm_complete",
    "llm_json",
    "get_langchain_chat",
]