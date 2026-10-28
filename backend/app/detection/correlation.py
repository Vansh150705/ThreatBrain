"""Pure correlation logic over recent alerted events of one entity (no I/O).

``services/correlation_service`` supplies the recent events from the event store;
the validation lab and the unit tests supply them directly. A correlation fires only
when the event being processed *completes* the pattern, so each completion yields one
hit and re-delivery of old events never re-fires an old pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.detection import attack_catalog
from app.detection.engine import SEVERITY_RANK, RuleError, RuleHit

CORRELATIONS_PATH = Path(__file__).with_name("correlations.yaml")
GROUP_FIELDS = {"source_ip", "username", "asset_name", "destination_ip"}
DISTINCT_KINDS = {"rule", "tactic", "technique", "username", "source_ip", "destination_ip", "asset_name"}
MAX_EVENTS_PER_GROUP = 300


@dataclass(frozen=True)
class Correlation:
    id: str
    name: str
    severity: str
    confidence: int
    techniques: tuple[str, ...]
    group_by: str
    window_minutes: int
    kind: str
    stages: tuple[dict[str, Any], ...] = ()
    select: dict[str, Any] = field(default_factory=dict)
    distinct: str = "rule"
    min: int = 2
    tests: tuple[dict[str, Any], ...] = ()

    @property
    def tactics(self) -> list[str]:
        return attack_catalog.tactics_for(list(self.techniques))


def _validate_selector(sel: Any, cid: str) -> dict[str, Any]:
    if not isinstance(sel, dict) or not any(sel.get(k) for k in ("rules", "tactics", "tags")):
        raise RuleError(f"{cid}: a stage/selector needs rules, tactics or tags")
    for k in ("rules", "tactics", "tags"):
        if k in sel and not (isinstance(sel[k], list) and all(isinstance(x, str) for x in sel[k])):
            raise RuleError(f"{cid}: selector {k} must be a list of strings")
    return sel


def correlation_from_dict(item: dict[str, Any]) -> Correlation:
    cid = str(item.get("id") or "")
    if not re.fullmatch(r"TB-COR-\d{3}", cid):
        raise RuleError(f"correlation id must look like TB-COR-001, got {cid!r}")
    if item.get("severity") not in SEVERITY_RANK:
        raise RuleError(f"{cid}: invalid severity")
    if item.get("group_by") not in GROUP_FIELDS:
        raise RuleError(f"{cid}: group_by must be one of {sorted(GROUP_FIELDS)}")
    window = int(item.get("window_minutes", 0))
    if not 1 <= window <= 1440:
        raise RuleError(f"{cid}: window_minutes must be 1-1440")
    kind = item.get("kind")
    techniques = list(item.get("techniques") or [])
    problems = attack_catalog.validate_ids(techniques)
    if problems:
        raise RuleError(f"{cid}: " + "; ".join(problems))
    common = dict(
        id=cid, name=str(item["name"]), severity=item["severity"],
        confidence=int(item.get("confidence", 70)), techniques=tuple(techniques),
        group_by=item["group_by"], window_minutes=window, kind=kind,
        tests=tuple(item.get("tests") or []),
    )
    if kind == "sequence":
        stages = [_validate_selector(s, cid) for s in item.get("stages") or []]
        if len(stages) < 2:
            raise RuleError(f"{cid}: a sequence needs at least two stages")
        return Correlation(**common, stages=tuple(stages))
    if kind == "threshold":
        distinct = item.get("distinct", "rule")
        if distinct not in DISTINCT_KINDS:
            raise RuleError(f"{cid}: distinct must be one of {sorted(DISTINCT_KINDS)}")
        n = int(item.get("min", 0))
        if n < 2:
            raise RuleError(f"{cid}: threshold min must be >= 2 (use a plain rule for single events)")
        return Correlation(**common, select=_validate_selector(item.get("select"), cid), distinct=distinct, min=n)
    raise RuleError(f"{cid}: kind must be 'sequence' or 'threshold'")


@lru_cache(maxsize=1)
def load_correlations() -> tuple[Correlation, ...]:
    raw = yaml.safe_load(CORRELATIONS_PATH.read_text(encoding="utf-8")) or {}
    out, seen = [], set()
    for item in raw.get("correlations") or []:
        c = correlation_from_dict(item)
        if c.id in seen:
            raise RuleError(f"duplicate correlation id {c.id}")
        seen.add(c.id)
        out.append(c)
    return tuple(out)


def _event_matches(ev: dict[str, Any], sel: dict[str, Any]) -> bool:
    rules, tactics, tags = set(sel.get("rules", [])), set(sel.get("tactics", [])), set(sel.get("tags", []))
    ids = set(ev.get("detections") or [])
    if ids & rules:
        return True
    return bool(set(ev.get("tactics") or []) & tactics) or bool(set(ev.get("tags") or []) & tags)


def _distinct_values(ev: dict[str, Any], kind: str, sel: dict[str, Any]) -> set[str]:
    if kind == "rule":
        ids = set(ev.get("detections") or [])
        return ids & set(sel["rules"]) if sel.get("rules") else ids
    if kind == "tactic":
        return set(ev.get("tactics") or []) & set(sel["tactics"]) if sel.get("tactics") else set(ev.get("tactics") or [])
    if kind == "technique":
        return set(ev.get("techniques") or [])
    v = ev.get(kind)
    return {str(v)} if v else set()


def evaluate(
    correlation: Correlation, current: dict[str, Any], recent: list[dict[str, Any]]
) -> RuleHit | None:
    """``current`` and each of ``recent`` are dicts with: id, at (datetime), detections (rule ids),
    tactics, techniques, tags, and the grouping fields. ``recent`` may include ``current``."""
    c = correlation
    key = current.get(c.group_by)
    if not key or not current.get("detections"):
        return None
    horizon = current["at"] - timedelta(minutes=c.window_minutes)
    group = [
        e for e in recent
        if e.get(c.group_by) == key and e["at"] >= horizon and e["at"] <= current["at"]
        and e.get("id") != current.get("id")
    ][-MAX_EVENTS_PER_GROUP:]
    group.sort(key=lambda e: e["at"])
    evidence: list[dict[str, Any]] = []

    if c.kind == "sequence":
        if not _event_matches(current, c.stages[-1]):
            return None
        stage_idx, chain = 0, []
        for ev in group:
            if stage_idx < len(c.stages) - 1 and _event_matches(ev, c.stages[stage_idx]):
                chain.append(ev)
                stage_idx += 1
        if stage_idx != len(c.stages) - 1:
            return None
        evidence = [*chain, current]
    else:
        if not _event_matches(current, c.select):
            return None
        values: set[str] = set()
        for ev in [*group, current]:
            if _event_matches(ev, c.select):
                got = _distinct_values(ev, c.distinct, c.select)
                if got - values:
                    evidence.append(ev)
                values |= got
        if len(values) < c.min:
            return None
        # fire only on the event that crosses the threshold, not on every event after it
        before: set[str] = set()
        for ev in group:
            if _event_matches(ev, c.select):
                before |= _distinct_values(ev, c.distinct, c.select)
        if len(before) >= c.min:
            return None

    return RuleHit(
        rule_id=c.id, name=c.name, severity=c.severity, confidence=c.confidence,
        tactics=c.tactics, techniques=list(c.techniques), tags=["correlation", f"group:{c.group_by}"],
        matched_fields=[c.group_by], evidence=[str(e["id"]) for e in evidence if e.get("id")], kind="correlation",
    )


def evaluate_all(current: dict[str, Any], recent: list[dict[str, Any]]) -> list[RuleHit]:
    return [h for c in load_correlations() if (h := evaluate(c, current, recent))]


def run_inline_tests(c: Correlation) -> list[dict[str, Any]]:
    """Execute a correlation's inline scenarios (events carry ``at`` minutes from t0)."""
    results = []
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    for i, t in enumerate(c.tests):
        evs = []
        for n, raw in enumerate(t["events"]):
            ev = {**raw, "id": f"e{n}", "at": t0 + timedelta(minutes=raw.get("at", n))}
            ev.setdefault("tactics", [])
            evs.append(ev)
        current = evs[-1]
        fired = evaluate(c, current, evs[:-1]) is not None
        results.append({"name": t.get("name") or f"test {i + 1}", "expected": bool(t["expect_fire"]),
                        "fired": fired, "passed": fired == bool(t["expect_fire"])})
    return results
