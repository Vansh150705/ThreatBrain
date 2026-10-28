"""Rule engine: evaluates the declarative rules in ``rules.yaml`` against an event."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.core.logging import get_logger
from app.detection.attack_catalog import tactics_for, validate_ids

log = get_logger(__name__)

RULES_PATH = Path(__file__).with_name("rules.yaml")
SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_MAX_TEXT = 20_000  # bound regex work on attacker-controlled input
_OPERATORS = {"equals", "contains", "startswith", "endswith", "regex", "in", "gt", "gte", "lt", "lte", "exists", "cidr"}


# a group containing an unbounded quantifier that is itself repeated: (a+)+  (a*)*  (a|b+)*  (.{1,}){2,}
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d*,\})")


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
    description: str = ""
    references: tuple[str, ...] = ()
    tuning: str = ""
    tests: tuple[dict[str, Any], ...] = ()   # [{name, event, expect_match}]
    source: str = "builtin"                    # builtin | custom | sigma
    version: int = 1


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
    evidence: list[str] = field(default_factory=list)   # ids of the events that completed a correlation
    kind: str = "rule"                                   # rule | correlation

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
            "kind": self.kind,
            **({"evidence": self.evidence} if self.evidence else {}),
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

    if op == "cidr":
        try:
            ip = ipaddress.ip_address(str(value).strip())
            nets = [ipaddress.ip_network(n, strict=False) for n in (arg if isinstance(arg, list) else [arg])]
        except ValueError:
            return False, None
        return any(ip in n for n in nets if n.version == ip.version), path

    text = value if isinstance(value, str) else json.dumps(value, default=str)
    text = text[:_MAX_TEXT]
    if op == "equals":
        return text.lower() == str(arg).lower(), path
    if op == "contains":
        return str(arg).lower() in text.lower(), path
    if op == "startswith":
        return text.lower().startswith(str(arg).lower()), path
    if op == "endswith":
        return text.lower().endswith(str(arg).lower()), path
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
        if len(node["regex"]) > 2000:
            raise RuleError(f"{rule_id}: regex longer than 2000 characters")
        if _NESTED_QUANTIFIER.search(node["regex"]):
            raise RuleError(
                f"{rule_id}: nested quantifier such as (a+)+ or (a*)* can backtrack catastrophically; rewrite it"
            )
        if re.search(r"\.\*|\.\+|\(\.\*\)|\+\+|\*\*", node["regex"]):
            raise RuleError(
                f"{rule_id}: unbounded wildcard (.* / .+) in regex; use a bounded gap such as .{{0,200}} "
                "to avoid catastrophic backtracking"
            )
    if ops[0] == "cidr":
        for n in node["cidr"] if isinstance(node["cidr"], list) else [node["cidr"]]:
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError as exc:
                raise RuleError(f"{rule_id}: bad cidr {n!r}") from exc


def rule_from_dict(item: dict[str, Any], *, source: str = "builtin") -> Rule:
    """Validate and build a Rule from its mapping form (YAML file row or DB row)."""
    rid = str(item.get("id") or item.get("rule_key") or "")
    if not rid:
        raise RuleError("rule is missing an id")
    sev = item.get("severity")
    if sev not in SEVERITY_RANK:
        raise RuleError(f"{rid}: invalid severity {sev!r}")
    if not item.get("name"):
        raise RuleError(f"{rid}: missing name")
    conf = int(item.get("confidence", 60))
    if not 0 <= conf <= 100:
        raise RuleError(f"{rid}: confidence must be 0-100")
    if "match" not in item:
        raise RuleError(f"{rid}: missing match")
    _validate(item["match"], rid)
    for t in item.get("tactics", []):
        if not re.fullmatch(r"TA\d{4}", str(t)):
            raise RuleError(f"{rid}: malformed tactic id {t!r}")
    for t in item.get("techniques", []):
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", str(t)):
            raise RuleError(f"{rid}: malformed technique id {t!r}")
    techniques = list(item.get("techniques", []))
    tactics = list(item.get("tactics", []))
    if source == "builtin":
        # built-in rules must use real, mutually consistent ATT&CK ids
        problems = validate_ids(techniques, tactics)
        if problems:
            raise RuleError(f"{rid}: " + "; ".join(problems))
    if not tactics:
        tactics = tactics_for(techniques)
    item = {**item, "tactics": tactics}
    return Rule(
        id=rid,
        name=str(item["name"]),
        severity=sev,
        confidence=conf,
        tactics=tuple(item.get("tactics", [])),
        techniques=tuple(item.get("techniques", [])),
        tags=tuple(item.get("tags", [])),
        match=item["match"],
        description=str(item.get("description") or ""),
        references=tuple(item.get("references") or item.get("rule_references") or []),
        tuning=str(item.get("tuning") or item.get("tuning_guidance") or ""),
        tests=tuple(item.get("tests") or []),
        source=source,
        version=int(item.get("version", 1)),
    )


def load_rule_file(path: Path = RULES_PATH) -> tuple[str, list[Rule]]:
    """Load a rules file. Accepts a bare list or ``{version: ..., rules: [...]}``."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    version = "0"
    if isinstance(raw, dict):
        version = str(raw.get("version", "0"))
        raw = raw.get("rules") or []
    rules: list[Rule] = []
    seen: set[str] = set()
    for item in raw:
        rule = rule_from_dict(item)
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id}")
        seen.add(rule.id)
        rules.append(rule)
    return version, rules


def load_rules(path: Path = RULES_PATH) -> list[Rule]:
    return load_rule_file(path)[1]


def run_rule_tests(rule: Rule) -> list[dict[str, Any]]:
    """Execute a rule's inline test events. Returns one result per test."""
    engine = RuleEngine([rule])
    results = []
    for i, t in enumerate(rule.tests):
        ev = dict(t.get("event") or {})
        ev.setdefault("title", "test event")
        ev.setdefault("event_type", "generic.event")
        ev.setdefault("raw_data", {})
        matched = bool(engine.evaluate(ev))
        expected = bool(t.get("expect_match", t.get("match", True)))
        results.append({"name": t.get("name") or f"test {i + 1}", "expected": expected, "matched": matched,
                        "passed": matched == expected})
    return results


class RuleEngine:
    def __init__(self, rules: list[Rule], version: str = "adhoc") -> None:
        self.rules = rules
        self.version = version

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
    """The built-in rule set (shared by every tenant; per-org tuning is layered on top)."""
    version, rules = load_rule_file()
    log.info("detection_rules_loaded", count=len(rules), version=version)
    return RuleEngine(rules, version=version)


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
