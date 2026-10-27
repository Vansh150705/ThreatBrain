"""Rule engine: evaluates the declarative rules in ``rules.yaml`` against an event."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.logging import get_logger

log = get_logger(__name__)

RULES_PATH = Path(__file__).with_name("rules.yaml")
SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_MAX_TEXT = 20_000  # bound regex work on attacker-controlled input
_OPERATORS = {"equals", "contains", "startswith", "regex", "in", "gt", "gte", "lt", "lte", "exists"}


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    confidence: int
    tactics: tuple[str, ...]
    techniques: tuple[str, ...]
    tags: tuple[str, ...]
    match: dict[str, Any]


@dataclass
class RuleHit:
    rule_id: str
    name: str
    severity: str
    confidence: int
    tactics: list[str]
    techniques: list[str]
    tags: list[str]
    matched_fields: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "tactics": self.tactics,
            "techniques": self.techniques,
            "tags": self.tags,
            "matched_fields": self.matched_fields,
        }


def _flatten_strings(value: Any, out: list[str], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        out.append(str(value))
    elif isinstance(value, dict):
        for v in value.values():
            _flatten_strings(v, out, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value[:200]:
            _flatten_strings(v, out, depth + 1)


def build_view(event: dict[str, Any]) -> dict[str, Any]:
    """Event dict + a ``text`` pseudo-field (all strings, bounded) + ``raw`` alias."""
    parts: list[str] = []
    _flatten_strings({k: v for k, v in event.items() if k != "raw_data"}, parts)
    _flatten_strings(event.get("raw_data") or {}, parts)
    view = dict(event)
    view["raw"] = event.get("raw_data") or {}
    view["text"] = " \n ".join(parts)[:_MAX_TEXT]
    return view


def _lookup(view: dict[str, Any], path: str) -> Any:
    cur: Any = view
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, dict):
            # case-insensitive key fallback (CloudTrail vs ECS naming)
            lowered = {str(k).lower(): v for k, v in cur.items()}
            if part.lower() in lowered:
                cur = lowered[part.lower()]
            else:
                return None
        else:
            return None
    return cur


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _leaf(cond: dict[str, Any], view: dict[str, Any]) -> tuple[bool, str | None]:
    path = cond["field"]
    value = _lookup(view, path)
    op = next(o for o in cond if o in _OPERATORS)
    arg = cond[op]

    if op == "exists":
        return (value is not None) == bool(arg), path
    if value is None:
        return False, None

    if op in ("gt", "gte", "lt", "lte"):
        n = _num(value)
        if n is None:
            return False, None
        ok = {"gt": n > arg, "gte": n >= arg, "lt": n < arg, "lte": n <= arg}[op]
        return ok, path

    if op == "in":
        wanted = {str(x).lower() for x in arg}
        return str(value).lower() in wanted, path

    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = text[:_MAX_TEXT]
    if op == "equals":
        return text.lower() == str(arg).lower(), path
    if op == "contains":
        return str(arg).lower() in text.lower(), path
    if op == "startswith":
        return text.lower().startswith(str(arg).lower()), path
    if op == "regex":
        return re.search(arg, text, re.IGNORECASE) is not None, path
    return False, None  # pragma: no cover - guarded by validation


def _evaluate(node: dict[str, Any], view: dict[str, Any], fields: list[str]) -> bool:
    if "all" in node:
        return all(_evaluate(n, view, fields) for n in node["all"])
    if "any" in node:
        return any(_evaluate(n, view, fields) for n in node["any"])
    if "not" in node:
        return not _evaluate(node["not"], view, [])
    ok, path = _leaf(node, view)
    if ok and path:
        fields.append(path)
    return ok


def _validate(node: Any, rule_id: str) -> None:
    if not isinstance(node, dict):
        raise RuleError(f"{rule_id}: match nodes must be mappings")
    if "all" in node or "any" in node:
        for child in node.get("all") or node.get("any"):
            _validate(child, rule_id)
        return
    if "not" in node:
        _validate(node["not"], rule_id)
        return
    if "field" not in node:
        raise RuleError(f"{rule_id}: leaf is missing 'field'")
    ops = [k for k in node if k in _OPERATORS]
    if len(ops) != 1:
        raise RuleError(f"{rule_id}: leaf needs exactly one operator, got {ops}")
    if ops[0] == "regex":
        try:
            re.compile(node["regex"])
        except re.error as exc:
            raise RuleError(f"{rule_id}: bad regex: {exc}") from exc


def load_rules(path: Path = RULES_PATH) -> list[Rule]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    rules: list[Rule] = []
    seen: set[str] = set()
    for item in raw:
        rid = item["id"]
        if rid in seen:
            raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        if item["severity"] not in SEVERITY_RANK:
            raise RuleError(f"{rid}: invalid severity {item['severity']!r}")
        _validate(item["match"], rid)
        rules.append(
            Rule(
                id=rid,
                name=item["name"],
                severity=item["severity"],
                confidence=int(item.get("confidence", 60)),
                tactics=tuple(item.get("tactics", [])),
                techniques=tuple(item.get("techniques", [])),
                tags=tuple(item.get("tags", [])),
                match=item["match"],
            )
        )
    return rules


class RuleEngine:
    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    def evaluate(self, event: dict[str, Any]) -> list[RuleHit]:
        """Return every rule that matches ``event`` (most severe first)."""
        view = build_view(event)
        hits: list[RuleHit] = []
        for rule in self.rules:
            fields: list[str] = []
            try:
                matched = _evaluate(rule.match, view, fields)
            except Exception:  # a broken rule must never take the pipeline down
                log.exception("rule_evaluation_failed", rule_id=rule.id)
                continue
            if matched:
                hits.append(
                    RuleHit(
                        rule_id=rule.id,
                        name=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        tactics=list(rule.tactics),
                        techniques=list(rule.techniques),
                        tags=list(rule.tags),
                        matched_fields=sorted(set(fields)),
                    )
                )
        hits.sort(key=lambda h: (-SEVERITY_RANK[h.severity], -h.confidence))
        return hits


@lru_cache(maxsize=1)
def get_engine() -> RuleEngine:
    rules = load_rules()
    log.info("detection_rules_loaded", count=len(rules))
    return RuleEngine(rules)


def summarize(hits: list[RuleHit]) -> dict[str, Any]:
    """Aggregate hits into the facts downstream stages consume."""
    if not hits:
        return {"matched": False, "severity_floor": None, "confidence": 0,
                "tactics": [], "techniques": [], "tags": [], "rules": []}

    def uniq(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    top = hits[0]
    return {
        "matched": True,
        "severity_floor": top.severity,
        "confidence": max(h.confidence for h in hits),
        "tactics": uniq([t for h in hits for t in h.tactics]),
        "techniques": uniq([t for h in hits for t in h.techniques]),
        "tags": uniq([t for h in hits for t in h.tags]),
        "rules": [h.as_dict() for h in hits],
    }
