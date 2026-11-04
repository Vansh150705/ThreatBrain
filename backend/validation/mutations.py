"""Semantics-preserving evasion mutations (metamorphic testing).

Take scenarios the platform already detects, rewrite the attacker-controlled text the way an evader would, and ask:
is it still detected? Because the mutations are mechanical and applied to EVERY eligible scenario, the result does not depend on
anyone choosing convenient examples. The same mutators are applied to benign scenarios to measure false-positive inflation.
All mutations are string transformations of telemetry; nothing is executed.
"""

from __future__ import annotations

import base64
import random
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

WINDOWS = re.compile(r"[A-Za-z]:\\|\.exe\b|\bcmd(\.exe)?\b|\bpowershell\b|\bwmic\b|\breg\b|\bnet\b|\bsc\b|\bschtasks\b", re.I)
POSIX = re.compile(r"(^|[\s;|&])(/bin/|/usr/|sudo\b|bash\b|sh\b|curl\b|wget\b|chmod\b|crontab\b|nc\b|python3?\b)")


def _is_windows(s: str) -> bool:
    return bool(WINDOWS.search(s)) and not POSIX.search(s)


def _is_posix(s: str) -> bool:
    return bool(POSIX.search(s)) and not _is_windows(s)


def case_swap(s: str, rnd: random.Random) -> str | None:
    if not _is_windows(s):
        return None
    return "".join(c.upper() if c.isalpha() and rnd.random() < 0.5 else c.lower() if c.isalpha() else c for c in s)


def space_pad(s: str, rnd: random.Random) -> str | None:
    return re.sub(r" ", lambda m: " " * rnd.choice([2, 3]) if rnd.random() < 0.6 else " ", s) if " " in s else None


def caret_insert(s: str, rnd: random.Random) -> str | None:
    if not _is_windows(s):
        return None
    first, _, rest = s.partition(" ")
    if len(first) < 4 or "\\" in first:
        return None
    i = rnd.randint(1, len(first) - 2)
    return first[:i] + "^" + first[i:] + (" " + rest if rest else "")


def quote_split(s: str, rnd: random.Random) -> str | None:
    first, _, rest = s.partition(" ")
    if len(first) < 4 or "\\" in first or "/" in first:
        return None
    i = rnd.randint(1, len(first) - 2)
    q = '""' if _is_windows(s) else "''"
    return first[:i] + q + first[i:] + (" " + rest if rest else "")


def comspec_wrap(s: str, rnd: random.Random) -> str | None:
    return f"%COMSPEC% /c {s}" if _is_windows(s) and not s.lower().startswith("powershell") else None


def abs_path(s: str, rnd: random.Random) -> str | None:
    first, _, rest = s.partition(" ")
    if "\\" in first or "/" in first or "=" in first or len(first) < 3:
        return None
    if _is_windows(s):
        exe = first if first.lower().endswith(".exe") else first + ".exe"
        return f"C:\\Windows\\System32\\{exe}" + (" " + rest if rest else "")
    if _is_posix(s):
        return f"/usr/bin/{first}" + (" " + rest if rest else "")
    return None


def ps_concat(s: str, rnd: random.Random) -> str | None:
    if "powershell" not in s.lower():
        return None
    changed = [0]

    def sub(m: re.Match[str]) -> str:
        body = m.group(2)
        if len(body) < 4 or changed[0] >= 3:
            return m.group(0)
        i = rnd.randint(1, len(body) - 1)
        changed[0] += 1
        return f"{m.group(1)}{body[:i]}{m.group(1)}+{m.group(1)}{body[i:]}{m.group(1)}"

    out = re.sub(r"(['\"])([A-Za-z0-9_.:/\\-]{4,40})\1", sub, s)
    return out if out != s else None


def ps_backtick(s: str, rnd: random.Random) -> str | None:
    if "powershell" not in s.lower():
        return None
    out = re.sub(r"\b([A-Z][A-Za-z]{5,})\b", lambda m: m.group(1)[:3] + "`" + m.group(1)[3:] if rnd.random() < 0.6 else m.group(1), s)
    return out if out != s else None


def ps_enc_wrap(s: str, rnd: random.Random) -> str | None:
    if "powershell" not in s.lower() and not _is_windows(s):
        return None
    return "powershell -nop -w hidden -enc " + base64.b64encode(s.encode("utf-16-le")).decode()


def sh_b64_wrap(s: str, rnd: random.Random) -> str | None:
    if not _is_posix(s):
        return None
    return f"echo {base64.b64encode(s.encode()).decode()} | base64 -d | sh"


def ifs_spaces(s: str, rnd: random.Random) -> str | None:
    if not _is_posix(s) or " " not in s:
        return None
    return s.replace(" ", "${IFS}", 6)


def url_double(s: str, rnd: random.Random) -> str | None:
    out = quote(s, safe="/?=&:-_.") if s else s
    return quote(out, safe="/?=&:-_.%") if out != s else None


MUTATORS_COMMAND: dict[str, Callable[[str, random.Random], str | None]] = {
    "case_swap": case_swap, "space_pad": space_pad, "caret_insert": caret_insert, "quote_split": quote_split,
    "comspec_wrap": comspec_wrap, "absolute_path": abs_path, "ps_string_concat": ps_concat, "ps_backtick": ps_backtick,
    "ps_encodedcommand_wrap": ps_enc_wrap, "sh_base64_pipe": sh_b64_wrap, "ifs_spaces": ifs_spaces,
}


def mutate_event(ev: dict[str, Any], name: str, rnd: random.Random) -> dict[str, Any] | None:
    """Return a copy of ``ev`` with the mutation applied to its attacker-controlled text, or None if not applicable."""
    cl = ev.get("command_line")
    if cl and name in MUTATORS_COMMAND:
        new = MUTATORS_COMMAND[name](str(cl), rnd)
        return {**ev, "command_line": new} if new and new != cl else None
    raw = ev.get("raw_data") or {}
    if name == "url_encode_twice":
        for k in ("url", "user_agent", "query"):
            if isinstance(raw.get(k), str):
                new = url_double(raw[k], rnd)
                if new:
                    return {**ev, "raw_data": {**raw, k: new}}
    return None


ALL = [*MUTATORS_COMMAND, "url_encode_twice"]
