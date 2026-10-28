"""Convert a (practical subset of) Sigma rule into a ThreatBrain rule definition.

Supported: selections as maps / lists of maps / keyword lists, field modifiers
(contains, startswith, endswith, re, all, cidr, gt/gte/lt/lte), ``*``/``?`` wildcards,
conditions with and / or / not / parentheses / ``1 of`` / ``all of`` (including ``sel*`` and ``them``),
``level`` -> severity, ``attack.tNNNN`` tags -> techniques.

Not supported (rejected with an explicit error, never silently dropped): aggregation
(``count``, ``near``, ``timeframe``), ``base64``/``windash`` and other transforming modifiers,
correlation rules. A converted rule is created as a draft; it only fires after an admin
adds tests that pass and enables it.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from app.detection import attack_catalog
from app.detection.engine import RuleError

LEVELS = {"informational": "info", "info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
FIELD_MAP = {
    "commandline": ("command_line", None),
    "image": ("process_name", "basename"),
    "originalfilename": ("process_name", "basename"),
    "parentimage": ("raw.parent_process", "basename"),
    "parentcommandline": ("raw.parent_command_line", None),
    "user": ("username", None),
    "username": ("username", None),
    "targetfilename": ("raw.file_path", None),
    "destinationip": ("destination_ip", None),
    "destinationport": ("destination_port", None),
    "sourceip": ("source_ip", None),
    "src_ip": ("source_ip", None),
    "dst_ip": ("destination_ip", None),
    "queryname": ("raw.query", None),
    "eventid": ("raw.event_code", None),
    "computername": ("asset_name", None),
    "hostname": ("asset_name", None),
    "targetobject": ("raw.registry_key", None),
    "details": ("raw.details", None),
}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "re", "all", "cidr", "gt", "gte", "lt", "lte"}
_UNSUPPORTED_CONDITION = re.compile(r"\|\s*(count|min|max|avg|sum|near)\b|\bnear\b", re.I)


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", s).strip("-")[:56] or "rule"


def _basename(v: str) -> str:
    return re.split(r"[\\/]", v)[-1]


def _wildcard_to_regex(v: str) -> str:
    return "^" + re.escape(v).replace(r"\*", ".{0,200}").replace(r"\?", ".") + "$"


def _leaf(field: str, mod: str | None, value: Any, post: str | None) -> dict[str, Any]:
    if value is None:
        return {"field": field, "exists": False}
    if isinstance(value, bool):
        value = str(value).lower()
    if mod in ("gt", "gte", "lt", "lte"):
        return {"field": field, mod: value}
    if mod == "cidr":
        return {"field": field, "cidr": value}
    v = str(value)
    if post == "basename" and mod in (None, "endswith", "contains"):
        v = _basename(v)
        if mod is None and "*" not in v and "?" not in v:
            return {"field": field, "equals": v}
    if mod == "re":
        return {"field": field, "regex": v}
    if mod in ("contains", "startswith", "endswith"):
        return {"field": field, mod: v}
    if "*" in v or "?" in v:
        return {"field": field, "regex": _wildcard_to_regex(v)}
    return {"field": field, "equals": v}


def _field_node(key: str, value: Any) -> dict[str, Any]:
    name, *mods = key.split("|")
    bad = [m for m in mods if m not in SUPPORTED_MODS]
    if bad:
        raise RuleError(f"unsupported Sigma modifier(s) {bad} on field {name!r}")
    require_all = "all" in mods
    mod = next((m for m in mods if m != "all"), None)
    field, post = FIELD_MAP.get(name.lower(), (f"raw.{name}", None))
    values = value if isinstance(value, list) else [value]
    leaves = [_leaf(field, mod, v, post) for v in values]
    if len(leaves) == 1:
        return leaves[0]
    return {"all" if require_all else "any": leaves}


def _selection_node(sel: Any, name: str) -> dict[str, Any]:
    if isinstance(sel, dict):
        parts = [_field_node(k, v) for k, v in sel.items()]
        return parts[0] if len(parts) == 1 else {"all": parts}
    if isinstance(sel, list):
        if all(isinstance(x, dict) for x in sel):
            alts = [_selection_node(x, name) for x in sel]
            return alts[0] if len(alts) == 1 else {"any": alts}
        if all(isinstance(x, (str, int)) for x in sel):  # keyword search over the whole event
            leaves = [{"field": "text", "contains": str(x)} for x in sel]
            return leaves[0] if len(leaves) == 1 else {"any": leaves}
    raise RuleError(f"selection {name!r} has an unsupported shape")


_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _Cond:
    def __init__(self, text: str, selections: dict[str, dict[str, Any]]) -> None:
        self.tokens = _TOKEN.findall(text)
        self.i = 0
        self.sel = selections

    def _peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def _next(self) -> str:
        tok = self._peek()
        if tok is None:
            raise RuleError("condition ended unexpectedly")
        self.i += 1
        return tok

    def parse(self) -> dict[str, Any]:
        node = self._or()
        if self._peek() is not None:
            raise RuleError(f"unexpected token {self._peek()!r} in condition")
        return node

    def _or(self) -> dict[str, Any]:
        parts = [self._and()]
        while (self._peek() or "").lower() == "or":
            self._next()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else {"any": parts}

    def _and(self) -> dict[str, Any]:
        parts = [self._not()]
        while (self._peek() or "").lower() == "and":
            self._next()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else {"all": parts}

    def _not(self) -> dict[str, Any]:
        if (self._peek() or "").lower() == "not":
            self._next()
            return {"not": self._not()}
        return self._atom()

    def _atom(self) -> dict[str, Any]:
        tok = self._next()
        if tok == "(":
            node = self._or()
            if self._next() != ")":
                raise RuleError("missing closing parenthesis in condition")
            return node
        if tok.lower() in ("1", "all") and (self._peek() or "").lower() == "of":
            self._next()
            target = self._next()
            names = (
                list(self.sel) if target.lower() == "them"
                else [n for n in self.sel if re.fullmatch(re.escape(target).replace(r"\*", ".*"), n)]
            )
            if not names:
                raise RuleError(f"no selection matches {target!r}")
            nodes = [self.sel[n] for n in names]
            if len(nodes) == 1:
                return nodes[0]
            return {"any" if tok == "1" else "all": nodes}
        if tok not in self.sel:
            raise RuleError(f"condition references unknown selection {tok!r}")
        return self.sel[tok]


def convert(sigma_text: str) -> dict[str, Any]:
    """Return ``{"rule": {...}, "warnings": [...]}``; raises RuleError when it cannot be converted faithfully."""
    if len(sigma_text) > 50_000:
        raise RuleError("Sigma document is too large (50 KB max)")
    try:
        doc = yaml.safe_load(sigma_text)
    except yaml.YAMLError as exc:
        raise RuleError(f"not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        raise RuleError("not a Sigma rule: missing a 'detection' section")
    det = dict(doc["detection"])
    condition = det.pop("condition", None)
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    if not isinstance(condition, str):
        raise RuleError("Sigma rule has no condition")
    if det.pop("timeframe", None):
        raise RuleError("unsupported: 'timeframe' (aggregation rules are not supported)")
    if _UNSUPPORTED_CONDITION.search(condition):
        raise RuleError("unsupported: aggregation/'near' conditions")
    selections = {name: _selection_node(body, name) for name, body in det.items()}
    match = _Cond(condition, selections).parse()

    warnings: list[str] = []
    tags = [str(t) for t in doc.get("tags") or []]
    techniques = sorted({m.group(1).upper() for t in tags if (m := re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t.lower()))})
    unknown = [t for t in techniques if not attack_catalog.is_known(t)]
    if unknown:
        warnings.append(f"technique(s) not in the ThreatBrain ATT&CK catalog (kept, but no tactic derived): {unknown}")
    if doc.get("logsource"):
        warnings.append("logsource is not enforced: the rule is evaluated against every event; narrow it with an event_type condition")
    level = LEVELS.get(str(doc.get("level", "medium")).lower())
    if level is None:
        raise RuleError(f"unknown Sigma level {doc.get('level')!r}")
    title = str(doc.get("title") or "").strip()
    if len(title) < 3:
        raise RuleError("Sigma rule needs a title")

    rule = {
        "rule_key": "sigma-" + _slug(title),
        "name": title[:200],
        "description": str(doc.get("description") or "")[:2000],
        "severity": level,
        "confidence": 55,
        "techniques": techniques,
        "tags": ["sigma"] + [t for t in tags if not t.lower().startswith("attack.")][:10],
        "references": [str(r) for r in (doc.get("references") or [])][:10],
        "match": match,
        "origin": "sigma",
        "sigma_source": sigma_text,
        "tests": [],
        "tuning_guidance": "; ".join(str(x) for x in (doc.get("falsepositives") or []))[:1000],
    }
    return {"rule": rule, "warnings": warnings}
