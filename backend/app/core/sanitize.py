"""Neutralise attacker-controlled text before it reaches storage, logs or JSON encoders.

PostgreSQL cannot store NUL (U+0000) in text/jsonb and rejects lone UTF-16 surrogates; JSON encoders reject
NaN/Infinity. Log lines are attacker-controlled, so each of these is a way to make an ingest request crash (500) or a
queue job fail forever. We replace rather than reject for text (the surrounding event is still useful evidence) and
reject non-finite numbers (they carry no evidence and have no JSON representation).
"""

from __future__ import annotations

import math
from typing import Any

MAX_DEPTH = 24


def clean_str(s: str) -> str:
    # surrogates -> U+FFFD (encode with 'replace' yields '?', which would hide that data was altered)
    s = "".join("�" if 0xD800 <= ord(c) <= 0xDFFF else c for c in s)
    return s.replace("\x00", "")


def clean_json(value: Any, _depth: int = 0) -> Any:
    if _depth > MAX_DEPTH:
        raise ValueError("value is nested too deeply")
    if isinstance(value, str):
        return clean_str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity are not allowed")
        return value
    if isinstance(value, dict):
        return {clean_str(str(k)): clean_json(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean_json(v, _depth + 1) for v in value]
    return value
