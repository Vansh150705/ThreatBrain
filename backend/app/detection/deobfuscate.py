"""Reversible-obfuscation normalisation applied before rules look at attacker-controlled text.

Rules are written against the *meaning* of a command or request, not its spelling. An attacker controls the
spelling, so each text field is also evaluated in a few decoded forms ("alternates"):

* shell      quotes / cmd ``^`` escapes / ``${IFS}`` / empty-string splices / repeated whitespace removed
* powershell string concatenation ``('i'+'ex')``, ``-f`` format strings, ``[char]105`` chains and backtick escapes folded
* url        percent-encoding decoded up to three layers (``%252e`` -> ``%2e`` -> ``.``)
* lookup     log4j style ``${lower:j}`` / ``${::-j}`` / ``${env:X:-j}`` lookups resolved
* base64     printable base64 payloads (UTF-8 or UTF-16LE, as PowerShell ``-enc`` uses) appended in the clear
* escapes    ``\\x41`` / ``\\u0041`` / octal escapes decoded

Nothing here executes anything; it is string rewriting bounded in work per event. Each decoder only runs when a cheap
marker is present, so ordinary text costs a handful of substring checks. A decoded form is only ever an *additional* view:
the original text is always evaluated first and a rule can still depend on the exact spelling.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote

MAX_LEN = 20_000
_MAX_PASSES = 8

_WS = re.compile(r"\s+")
_ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
_IFS = re.compile(r"\$\{IFS[^}]{0,8}\}|\$IFS(?:\$\d)?")
_EMPTY_QUOTES = re.compile(r"(''|\"\")")

# PowerShell: 'a'+'b'  "a"+"b"  'a' + "b"
_PS_CONCAT = re.compile(r"""(['"])((?:(?!\1).){0,200})\1\s*\+\s*(['"])((?:(?!\3).){0,200})\3""", re.S)
_PS_FORMAT = re.compile(r"""(['"])((?:\{\d+\}|(?!\1)[^{}]){1,200})\1\s*-f\s*((?:\s*['"][^'"]{0,60}['"]\s*,?){1,10})""", re.I)
_PS_FORMAT_ARG = re.compile(r"""['"]([^'"]{0,60})['"]""")
_PS_CHAR = re.compile(r"\[char\]\s*(?:\(\s*(\d{2,3})\s*\)|(\d{2,3}))", re.I)
_PS_CHAR_PLUS = re.compile(r"(?<=[A-Za-z0-9])\s*\+\s*(?=[A-Za-z0-9])")
_BACKTICK = re.compile(r"`(?=[A-Za-z0-9_])")
_QUOTE_CHARS = re.compile(r"['\"]")

_PS_MARKER = re.compile(r"['\"]\s*\+\s*['\"]")
_URL_ESC = re.compile(r"%[0-9a-fA-F]{2}")
_UNICODE_ESC = re.compile(r"(?:\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|%u([0-9a-fA-F]{4}))")
_OCTAL_ESC = re.compile(r"\\([0-7]{3})")

_LOOKUP = re.compile(r"\$\{(?:(lower|upper):([^${}]{0,40})|(?:[a-z]{0,8}:)?(?:[^${}:]{0,20}):-([^${}]{0,40})|:+-([^${}]{0,40}))\}", re.I)

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=_-])")
_B64_SPACED = re.compile(r"(?<![A-Za-z0-9+/])((?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return ok / len(s)


def _decode_b64(token: str) -> str | None:
    token = token.strip()
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not 6 <= len(raw) <= 8192:
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        # utf-16 decode of utf-8 bytes yields CJK noise; require mostly ASCII-range text
        ascii_ratio = sum(1 for c in text if ord(c) < 128) / max(1, len(text))
        if _printable_ratio(text) >= 0.95 and ascii_ratio >= 0.9 and len(text.strip()) >= 4:
            return text
    return None


def _fold_concat(text: str) -> str:
    prev = None
    for _ in range(_MAX_PASSES):
        if prev == text:
            break
        prev = text
        text = _PS_CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
    return text


def _fold_format(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        args = _PS_FORMAT_ARG.findall(m.group(3))
        out = m.group(2)
        try:
            return "'" + re.sub(r"\{(\d+)\}", lambda k: args[int(k.group(1))], out) + "'"
        except IndexError:
            return m.group(0)

    return _PS_FORMAT.sub(sub, text)


def powershell(text: str) -> str:
    """Fold the common PowerShell string-building tricks into the string they produce."""
    t = _BACKTICK.sub("", text)
    t = _PS_CHAR.sub(lambda m: chr(int(m.group(1) or m.group(2))), t)
    t = _fold_format(t)
    t = _fold_concat(t)
    # [char]105+[char]101 left bare words joined by '+'
    t = _PS_CHAR_PLUS.sub("", t) if "[char]" in text.lower() else t
    return t


def shell(text: str) -> str:
    """Drop quote/escape splicing: ``w'h'oami``, ``c""at``, ``cmd /c ^w^h^o^a^m^i``, ``cat${IFS}/etc/passwd``."""
    t = text
    if "$'" in t:
        t = _ANSI_C.sub(lambda m: _unescape(m.group(1)), t)
    t = _IFS.sub(" ", t)
    t = _QUOTE_CHARS.sub("", t).replace("^", "")
    if "\\" in t and not re.search(r"[A-Za-z]:\\|\\\\[\w.$-]+\\", t):   # POSIX line: ba\sh -> bash (never touch Windows paths)
        t = re.sub(r"\\(?=[A-Za-z0-9_])", "", t)
    return _WS.sub(" ", t)


def squash(text: str) -> str:
    """The original, conservative layer (kept as a distinct form): quotes, carets, whitespace."""
    return _WS.sub(" ", text.replace('"', "").replace("^", ""))


def _unescape(text: str) -> str:
    def u(m: re.Match[str]) -> str:
        code = m.group(1) or m.group(2) or m.group(3)
        try:
            return chr(int(code, 16))
        except ValueError:
            return m.group(0)

    t = _UNICODE_ESC.sub(u, text)
    return _OCTAL_ESC.sub(lambda m: chr(int(m.group(1), 8)) if int(m.group(1), 8) < 256 else m.group(0), t)


def url_decode(text: str, layers: int = 3) -> str:
    t = text
    for _ in range(layers):
        if not _URL_ESC.search(t):
            break
        d = unquote(t, errors="replace")
        if d == t:
            break
        t = d
    return t


def lookups(text: str) -> str:
    """Resolve ``${lower:j}``, ``${upper:x}``, ``${::-j}``, ``${env:NAME:-j}`` innermost-first."""
    t = text
    for _ in range(_MAX_PASSES):
        def sub(m: re.Match[str]) -> str:
            if m.group(1):
                return m.group(2).lower() if m.group(1).lower() == "lower" else m.group(2).upper()
            return m.group(3) if m.group(3) is not None else (m.group(4) or "")

        n = _LOOKUP.sub(sub, t)
        if n == t:
            break
        t = n
    return t


def base64_payloads(text: str, limit: int = 6) -> str:
    out: list[str] = []
    for rx in (_B64, _B64_SPACED):
        for m in rx.finditer(text):
            dec = _decode_b64(m.group(1))
            if dec and dec not in out:
                out.append(dec)
            if len(out) >= limit:
                break
    return " ".join(out)


def alternates(text: str, *, command: bool = False) -> tuple[str, ...]:
    """Distinct decoded forms of ``text`` (never including ``text`` itself), cheapest triggers first."""
    if not text:
        return ()
    text = text[:MAX_LEN]
    forms: list[str] = []

    def add(candidate: str) -> None:
        if candidate and candidate != text and candidate not in forms:
            forms.append(candidate)

    low = text.lower()
    windows_path = re.search(r"[A-Za-z]:\\|\\\\[\w.$-]+\\", text) is not None
    shell_needed = (
        '"' in text or "'" in text or "^" in text or "IFS" in text or "$'" in text
        or ("\\" in text and not windows_path)
    )
    if command and (shell_needed or "  " in text or "\t" in text):
        add(squash(text))
    ps = None
    if command and ("`" in text or "[char]" in low or _PS_MARKER.search(text) or ("-f" in low and "{0}" in text)):
        ps = powershell(text)
        add(ps)
        add(_QUOTE_CHARS.sub("", ps))     # ('iex') -> (iex)
    if command and shell_needed:
        add(shell(text))
        if ps:
            add(shell(ps))
    if "%" in text:
        add(url_decode(text))
    if "${" in text:
        add(lookups(text))
    if "\\u" in low or "\\x" in low or "%u" in low or re.search(r"\\[0-7]{3}", text):
        add(_unescape(text))
    if len(text) >= 24:
        b = base64_payloads(text)
        if b:
            add(text + " " + b)
            # the decoded blob can itself be obfuscated PowerShell
            if command:
                add(powershell(b))
    return tuple(forms)
