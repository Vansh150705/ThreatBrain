"""Per-organization detection engine: built-in rules + tenant overrides + tenant custom rules.

The built-in set is shared and immutable at runtime. A tenant can disable a built-in
rule or change its severity (``rule_overrides``) and can add custom rules
(``detection_rules`` with status ``enabled``). The merged engine is cached for
``RULE_CACHE_SECONDS`` and dropped immediately when that tenant edits rules.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from typing import Any

from app.core.logging import get_logger
from app.detection.engine import Rule, RuleEngine, RuleError, get_engine, rule_from_dict
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

RULE_CACHE_SECONDS = 30.0
_cache: dict[str, tuple[float, RuleEngine]] = {}
_lock = threading.Lock()


def invalidate(org_id: str | None = None) -> None:
    with _lock:
        if org_id is None:
            _cache.clear()
        else:
            _cache.pop(str(org_id), None)


def _build(org_id: str) -> RuleEngine:
    base = get_engine()
    client = get_supabase_admin()
    overrides = {
        r["rule_key"]: r
        for r in (client.table("rule_overrides").select("*").eq("organization_id", org_id).execute().data or [])
    }
    rules: list[Rule] = []
    for rule in base.rules:
        ov = overrides.get(rule.id)
        if ov:
            if not ov.get("enabled", True):
                continue
            if ov.get("severity_override"):
                rule = dataclasses.replace(rule, severity=ov["severity_override"])
        rules.append(rule)
    custom_rows = (
        client.table("detection_rules").select("*").eq("organization_id", org_id)
        .eq("status", "enabled").is_("deleted_at", "null").execute().data or []
    )
    builtin_ids = {r.id for r in base.rules}
    for row in custom_rows:
        try:
            custom = rule_from_dict(row, source="sigma" if row.get("origin") == "sigma" else "custom")
        except RuleError as exc:  # a bad stored rule must not take detection down for the tenant
            log.warning("custom_rule_skipped", org_id=org_id, rule_key=row.get("rule_key"), error=str(exc))
            continue
        if custom.id in builtin_ids:
            continue
        rules.append(custom)
    return RuleEngine(rules, version=f"{base.version}+org:{len(custom_rows)}c/{len(overrides)}o")


def get_org_engine(org_id: str) -> RuleEngine:
    org_id = str(org_id)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(org_id)
        if hit and now - hit[0] < RULE_CACHE_SECONDS:
            return hit[1]
    try:
        engine = _build(org_id)
    except Exception:
        log.exception("org_engine_build_failed", org_id=org_id)
        return get_engine()  # fail open to the shared rules rather than stop detecting
    with _lock:
        _cache[org_id] = (now, engine)
    return engine


def evaluate(org_id: str, event: dict[str, Any]):
    return get_org_engine(org_id).evaluate(event)
