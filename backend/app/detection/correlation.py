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


RATE_DISTINCT = {"username", "source_ip", "destination_ip", "asset_name"}


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
    max_evidence: int = 50
    tests: tuple[dict[str, Any], ...] = ()

    @property
    def tactics(self) -> list[str]:
        return attack_catalog.tactics_for(list(self.techniques))


def _validate_selector(sel: Any, cid: str, *, allow_event_types: bool = False) -> dict[str, Any]:
    keys = ("rules", "tactics", "tags") + (("event_types",) if allow_event_types else ())
    if not isinstance(sel, dict) or not any(sel.get(k) for k in keys):
        raise RuleError(f"{cid}: a stage/selector needs one of {', '.join(keys)}")
    for k in keys:
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
    if kind == "rate":
        sel = _validate_selector(item.get("select"), cid, allow_event_types=True)
        if not sel.get("event_types"):
            raise RuleError(f"{cid}: a rate correlation selects on event_types")
        distinct = item.get("distinct")
        if distinct is not None and distinct not in RATE_DISTINCT:
            raise RuleError(f"{cid}: distinct must be one of {sorted(RATE_DISTINCT)}")
        n = int(item.get("min", 0))
        if n < 3:
            raise RuleError(f"{cid}: rate min must be >= 3")
        return Correlation(**common, select=sel, distinct=distinct or "", min=n)
    raise RuleError(f"{cid}: kind must be 'sequence', 'threshold' or 'rate'")


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
    if sel.get("event_types") and ev.get("event_type") in set(sel["event_types"]):
        return True
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


@dataclass(frozen=True)
class Match:
    key: str                      # stable id of this completion; the ledger uses it to report each completion once
    evidence: tuple[str, ...]


def _order(e: dict[str, Any]) -> tuple[Any, str]:
    return (e["at"], str(e.get("id", "")))


def _sequence_matches(c: Correlation, group_value: str, events: list[dict[str, Any]]) -> list[Match]:
    window = timedelta(minutes=c.window_minutes)
    out: list[Match] = []
    for f in events:
        if not _event_matches(f, c.stages[-1]) or not f.get("detections"):
            continue
        idx, chain = 0, []
        for e in events:
            if _order(e) >= _order(f) or e["at"] < f["at"] - window:
                continue
            if idx < len(c.stages) - 1 and e.get("detections") and _event_matches(e, c.stages[idx]):
                chain.append(e)
                idx += 1
        if idx == len(c.stages) - 1:
            out.append(Match(f"{c.id}:{group_value}:{f['id']}", tuple(str(x["id"]) for x in [*chain, f])))
    return out


def _count_matches(c: Correlation, group_value: str, events: list[dict[str, Any]]) -> list[Match]:
    """threshold (distinct values of detections/tactics) and rate (event counts / distinct field) share one scan."""
    window = timedelta(minutes=c.window_minutes)
    members = [e for e in events if _event_matches(e, c.select) and (c.kind == "rate" or e.get("detections"))]

    def count(evs: list[dict[str, Any]]) -> int:
        if c.kind == "rate":
            return len({e.get(c.distinct) for e in evs if e.get(c.distinct)}) if c.distinct else len(evs)
        vals: set[str] = set()
        for e in evs:
            vals |= _distinct_values(e, c.distinct, c.select)
        return len(vals)

    out: list[Match] = []
    seen_buckets: set[int] = set()
    for i, e in enumerate(members):
        in_window = [m for m in members[: i + 1] if m["at"] >= e["at"] - window]
        if count(in_window) < c.min:
            continue
        bucket = int(in_window[0]["at"].timestamp() // (c.window_minutes * 60))
        if bucket in seen_buckets:
            continue
        seen_buckets.add(bucket)
        out.append(Match(f"{c.id}:{group_value}:{bucket}", tuple(str(x["id"]) for x in in_window[-c.max_evidence:])))
        break   # one report per scan; later crossings in the same burst share the bucket key
    return out


def find_matches(c: Correlation, events: list[dict[str, Any]], group_value: str) -> list[Match]:
    """All completions of ``c`` among ``events`` of one group, independent of the order they were processed in."""
    ordered = sorted((e for e in events if e.get(c.group_by) == group_value), key=_order)[-MAX_EVENTS_PER_GROUP:]
    return _sequence_matches(c, group_value, ordered) if c.kind == "sequence" else _count_matches(c, group_value, ordered)


def evaluate_all(current: dict[str, Any], recent: list[dict[str, Any]]) -> list[RuleHit]:
    """Correlation hits visible once ``current`` is part of the event store.

    Symmetric by design: events are processed concurrently by independent workers, so the event that
    happens to be processed *last* is not necessarily the last in time. Every processor therefore looks
    at the whole group and reports any completion it can see; ``Match.key`` is stable across processors
    so the ledger (see correlation_service) lets exactly one of them report it.
    """
    pool = {str(e["id"]): e for e in recent}
    pool[str(current["id"])] = current
    events = list(pool.values())
    hits: list[RuleHit] = []
    for c in load_correlations():
        value = current.get(c.group_by)
        if not value:
            continue
        for m in find_matches(c, events, value):
            hits.append(RuleHit(
                rule_id=c.id, name=c.name, severity=c.severity, confidence=c.confidence, tactics=c.tactics,
                techniques=list(c.techniques), tags=["correlation", f"group:{c.group_by}"], matched_fields=[c.group_by],
                evidence=list(m.evidence)[-c.max_evidence:], kind="correlation", dedupe_key=m.key,
            ))
    return hits


def rate_event_types() -> set[str]:
    return {t for c in load_correlations() if c.kind == "rate" for t in c.select.get("event_types", [])}


def run_inline_tests(c: Correlation) -> list[dict[str, Any]]:
    """Execute a correlation's inline scenarios (events carry ``at`` minutes from t0).

    Each scenario is evaluated with every event in turn as the 'last processed' one, in both the given and the
    reversed processing order: the result must not depend on order (a completion is seen by someone, and by the
    same stable key from everyone who sees it).
    """
    results = []
    t0 = datetime(2026, 1, 1, 12, 0, 0)
    for i, t in enumerate(c.tests):
        evs = []
        for n, raw in enumerate(t["events"]):
            ev = {**raw, "id": f"e{n}", "at": t0 + timedelta(minutes=raw.get("at", n))}
            ev.setdefault("tactics", [])
            evs.append(ev)
        keys_by_order: list[set[str]] = []
        for processing in (evs, list(reversed(evs))):
            seen: set[str] = set()
            for k, cur in enumerate(processing):
                visible = processing[: k + 1]      # events already written to the store when `cur` is processed
                seen |= {h.dedupe_key for h in evaluate_all(cur, visible[:-1]) if h.rule_id == c.id}
            keys_by_order.append(seen)
        fired = bool(keys_by_order[0])
        consistent = keys_by_order[0] == keys_by_order[1]
        results.append({"name": t.get("name") or f"test {i + 1}", "expected": bool(t["expect_fire"]), "fired": fired,
                        "passed": fired == bool(t["expect_fire"]) and consistent})
    return results
