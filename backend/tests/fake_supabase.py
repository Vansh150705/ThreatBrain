"""In-memory stand-in for the Supabase/PostgREST client used by the backend.

It is *schema aware*: table columns are parsed from ``database/migrations`` so a
query that selects, filters on or writes a column that does not exist fails here
the same way PostgREST would fail in production. It implements only the query
builder surface the backend uses (select/insert/upsert/update/delete, eq/neq/
in_/is_/gt(e)/lt(e)/contains/ilike, order/limit/range, ``not_``).
"""

from __future__ import annotations

import copy
import re
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

MIGRATIONS = Path(__file__).resolve().parents[2] / "database" / "migrations"

_NOT_COLUMN = {
    "constraint", "primary", "unique", "check", "foreign", "references", "on",
    "default", "not", "null", "create", "alter", "comment", "using", "with",
}


class APIError(Exception):
    """Mirrors postgrest.exceptions.APIError closely enough for the backend."""


def _parse_schema() -> dict[str, set[str]]:
    schema: dict[str, set[str]] = {}
    for path in sorted(MIGRATIONS.glob("*.sql")):
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        for m in re.finditer(
            r"CREATE TABLE(?: IF NOT EXISTS)?\s+public\.(\w+)\s*\((.*?)\n\);", sql, re.S | re.I
        ):
            cols: set[str] = set()
            depth = 0
            for line in m.group(2).split("\n"):
                stripped = line.strip()
                if depth == 0:
                    tok = re.match(r"([a-z_][a-z0-9_]*)\s+\S", stripped, re.I)
                    if tok and tok.group(1).lower() not in _NOT_COLUMN:
                        cols.add(tok.group(1).lower())
                depth += line.count("(") - line.count(")")
            schema[m.group(1).lower()] = cols
        for m in re.finditer(r"ALTER TABLE\s+public\.(\w+)(.*?);", sql, re.S | re.I):
            for col in re.finditer(r"ADD COLUMN(?: IF NOT EXISTS)?\s+(\w+)", m.group(2), re.I):
                schema.setdefault(m.group(1).lower(), set()).add(col.group(1).lower())
    return schema


SCHEMA = _parse_schema()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _short(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


# Column defaults mirroring the SQL DEFAULT clauses the backend relies on.
_DEFAULTS: dict[str, dict[str, Any]] = {
    "threats": {
        "short_id": lambda: _short("THR"), "severity": "medium", "status": "open",
        "confidence": 50, "risk_score": 0, "mitre_tactics": list, "mitre_techniques": list,
        "attack_chain": list, "source_ips": list, "target_ips": list, "affected_users": list,
        "iocs": dict, "enrichment": dict, "ai_analysis": dict, "tags": list,
        "detected_at": _now, "deleted_at": None, "incident_id": None,
    },
    "incidents": {
        "short_id": lambda: _short("INC"), "severity": "medium", "status": "open",
        "priority": "p3", "confidence": 50, "risk_score": 0, "threat_count": 0,
        "asset_count": 0, "kill_chain": list, "mitre_tactics": list, "mitre_techniques": list,
        "affected_asset_ids": list, "source_ips": list, "attribution": dict, "timeline": list,
        "playbook_runs": list, "ai_summary": dict, "tags": list, "first_seen_at": _now,
        "last_seen_at": _now, "deleted_at": None, "assigned_to": None,
    },
    "audit_logs": {"short_id": lambda: _short("AUD"), "severity": "info", "status": "success",
                   "changes": dict, "metadata": dict},
    "playbook_approvals": {"status": "pending", "priority": 5, "execution_status": None},
    "agents": {"enabled": True, "status": "idle", "total_runs": 0, "successful_runs": 0,
               "failed_runs": 0, "avg_latency_ms": 0},
    "agent_runs": {"status": "completed"},
    "iocs": {"times_seen": 1},
    "users": {"status": "active", "role": "viewer", "deleted_at": None},
    "playbooks": {"enabled": True, "auto_execute": False, "approval_required": True, "steps": list},
    "api_keys": {"revoked_at": None, "last_used_at": None},
    "pipeline_runs": {"status": "queued"},
    "organizations": {"status": "active", "plan": "free", "deleted_at": None, "settings": dict},
}
_UNIQUE: dict[str, list[tuple[str, ...]]] = {
    "agents": [("organization_id", "agent_key")],
    "iocs": [("organization_id", "ioc_type", "normalized_value")],
    "api_keys": [("key_hash",)],
}
_APPEND_ONLY = {"audit_logs"}


class FakeResult:
    def __init__(self, data: list[dict[str, Any]] | None, count: int | None = None) -> None:
        self.data = data
        self.count = count


def _resolve(row: dict[str, Any], column: str) -> Any:
    if "->>" in column:
        base, key = column.split("->>", 1)
        val = row.get(base)
        return val.get(key) if isinstance(val, dict) else None
    return row.get(column)


def _cmp_key(v: Any) -> Any:
    return (v is None, v)


class _Not:
    def __init__(self, q: "FakeQuery") -> None:
        self._q = q

    def is_(self, col: str, val: Any) -> "FakeQuery":
        self._q._add_filter(col, lambda v: not _is(v, val))
        return self._q

    def eq(self, col: str, val: Any) -> "FakeQuery":
        self._q._add_filter(col, lambda v: v != val)
        return self._q

    def in_(self, col: str, vals: list[Any]) -> "FakeQuery":
        self._q._add_filter(col, lambda v: v not in vals)
        return self._q


def _is(v: Any, val: Any) -> bool:
    if val in ("null", None):
        return v is None
    if val in ("true", True):
        return v is True
    if val in ("false", False):
        return v is False
    return v == val


class FakeQuery:
    def __init__(self, db: "FakeSupabase", table: str) -> None:
        self.db = db
        self.table = table
        self.op = "select"
        self.cols = "*"
        self.count_mode: str | None = None
        self.payload: Any = None
        self.on_conflict: str | None = None
        self.filters: list[tuple[str, Any]] = []
        self.order_by: list[tuple[str, bool]] = []
        self.limit_n: int | None = None
        self.range_: tuple[int, int] | None = None
        self.single_mode = False
        self.not_ = _Not(self)

    # ---- builders ------------------------------------------------------
    def select(self, cols: str = "*", count: str | None = None) -> "FakeQuery":
        self.cols, self.count_mode = cols, count
        return self

    def insert(self, payload: Any) -> "FakeQuery":
        self.op, self.payload = "insert", payload
        return self

    def upsert(self, payload: Any, on_conflict: str | None = None) -> "FakeQuery":
        self.op, self.payload, self.on_conflict = "upsert", payload, on_conflict
        return self

    def update(self, payload: dict[str, Any]) -> "FakeQuery":
        self.op, self.payload = "update", payload
        return self

    def delete(self) -> "FakeQuery":
        self.op = "delete"
        return self

    def _add_filter(self, col: str, pred: Any) -> None:
        self.filters.append((col, pred))

    def eq(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: _norm(v) == _norm(val))
        return self

    def neq(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: _norm(v) != _norm(val))
        return self

    def in_(self, col: str, vals: list[Any]) -> "FakeQuery":
        nv = [_norm(x) for x in vals]
        self._add_filter(col, lambda v: _norm(v) in nv)
        return self

    def is_(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: _is(v, val))
        return self

    def gte(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: v is not None and _norm(v) >= _norm(val))
        return self

    def gt(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: v is not None and _norm(v) > _norm(val))
        return self

    def lte(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: v is not None and _norm(v) <= _norm(val))
        return self

    def lt(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: v is not None and _norm(v) < _norm(val))
        return self

    def contains(self, col: str, vals: Any) -> "FakeQuery":
        want = vals if isinstance(vals, list) else [vals]
        self._add_filter(
            col, lambda v: isinstance(v, list) and all(_norm(x) in [_norm(y) for y in v] for x in want)
        )
        return self

    def ilike(self, col: str, pattern: str) -> "FakeQuery":
        rx = re.compile("^" + re.escape(pattern).replace("%", ".*") + "$", re.I)
        self._add_filter(col, lambda v: v is not None and bool(rx.match(str(v))))
        return self

    def order(self, col: str, desc: bool = False, **_: Any) -> "FakeQuery":
        self.order_by.append((col, desc))
        return self

    def limit(self, n: int) -> "FakeQuery":
        self.limit_n = n
        return self

    def range(self, start: int, end: int) -> "FakeQuery":
        self.range_ = (start, end)
        return self

    def maybe_single(self) -> "FakeQuery":
        self.single_mode = True
        return self

    # ---- execution -----------------------------------------------------
    def _check_columns(self, cols: list[str]) -> None:
        known = SCHEMA.get(self.table)
        if known is None:
            raise APIError(f'relation "public.{self.table}" does not exist')
        for c in cols:
            base = c.split("->>")[0].split("->")[0]
            if base not in known:
                raise APIError(f'column {self.table}.{base} does not exist')

    def execute(self) -> FakeResult:
        with self.db.lock:
            return self._execute()

    def _execute(self) -> FakeResult:
        rows = self.db.tables.setdefault(self.table, [])
        if self.table not in SCHEMA:
            raise APIError(f'relation "public.{self.table}" does not exist')

        if self.op in ("insert", "upsert"):
            items = self.payload if isinstance(self.payload, list) else [self.payload]
            out = []
            for item in items:
                self._check_columns(list(item.keys()))
                out.append(self._insert_one(rows, item))
            return FakeResult(copy.deepcopy(out))

        self._check_columns([c for c, _ in self.filters])
        if self.cols != "*":
            self._check_columns([c.strip() for c in self.cols.split(",") if c.strip()])
        matched = [r for r in rows if all(p(_resolve(r, c)) for c, p in self.filters)]

        if self.op == "update":
            if self.table in _APPEND_ONLY:
                raise APIError("audit_logs is append-only")
            self._check_columns(list(self.payload.keys()))
            for r in matched:
                for k, v in self.payload.items():
                    r[k] = _now() if v == "now()" else copy.deepcopy(v)
                if "updated_at" in SCHEMA[self.table]:
                    r["updated_at"] = _now()
            return FakeResult(copy.deepcopy(matched))

        if self.op == "delete":
            if self.table in _APPEND_ONLY:
                raise APIError("audit_logs is append-only")
            for r in matched:
                rows.remove(r)
            return FakeResult(copy.deepcopy(matched))

        for col, desc in reversed(self.order_by):
            matched.sort(key=lambda r, c=col: _cmp_key(_resolve(r, c)), reverse=desc)
        total = len(matched)
        if self.range_:
            matched = matched[self.range_[0] : self.range_[1] + 1]
        elif self.limit_n is not None:
            matched = matched[: self.limit_n]
        if self.cols != "*":
            wanted = [c.strip() for c in self.cols.split(",") if c.strip()]
            matched = [{c: copy.deepcopy(r.get(c.split("->>")[0])) for c in wanted} for r in matched]
        else:
            matched = copy.deepcopy(matched)
        if self.single_mode:
            return FakeResult(matched[0] if matched else None, total)
        return FakeResult(matched, total if self.count_mode else None)

    def _insert_one(self, rows: list[dict[str, Any]], item: dict[str, Any]) -> dict[str, Any]:
        new: dict[str, Any] = {}
        for k, dv in _DEFAULTS.get(self.table, {}).items():
            new[k] = dv() if callable(dv) else dv
        new["id"] = item.get("id") or str(uuid.uuid4())
        for k, v in item.items():
            new[k] = _now() if v == "now()" else copy.deepcopy(v)
        cols = SCHEMA[self.table]
        if "created_at" in cols:
            new.setdefault("created_at", _now())
        if "updated_at" in cols:
            new.setdefault("updated_at", _now())
        if "organization_id" in cols and "organization_id" not in new:
            new["organization_id"] = None

        keys = _UNIQUE.get(self.table, [])
        if self.on_conflict:
            keys = [tuple(c.strip() for c in self.on_conflict.split(","))]
        for key in keys:
            for existing in rows:
                if all(_norm(existing.get(c)) == _norm(new.get(c)) for c in key):
                    if self.op == "upsert":
                        existing.update({k: v for k, v in new.items() if k != "id" and k in item})
                        return existing
                    raise APIError(f"duplicate key value violates unique constraint {key}")
        rows.append(new)
        return new


def _norm(v: Any) -> Any:
    if isinstance(v, uuid.UUID):
        return str(v)
    return v


class _AuthAdmin:
    def __init__(self, db: "FakeSupabase") -> None:
        self.db = db

    def create_user(self, attrs: dict[str, Any]) -> Any:
        email = attrs["email"]
        if any(u["email"] == email for u in self.db.auth_users.values()):
            raise APIError("A user with this email address has already been registered")
        uid = str(uuid.uuid4())
        self.db.auth_users[uid] = {"id": uid, "email": email, "password": attrs["password"]}
        self.db.tables.setdefault("users", []).append(
            {"id": uid, "email": email, "full_name": attrs.get("user_metadata", {}).get("full_name"),
             "organization_id": None, "role": "viewer", "status": "active", "deleted_at": None,
             "avatar_url": None}
        )
        return SimpleNamespace(user=SimpleNamespace(id=uid))

    def delete_user(self, uid: str) -> None:
        self.db.auth_users.pop(uid, None)
        self.db.tables["users"] = [u for u in self.db.tables.get("users", []) if u["id"] != uid]


class FakeSupabase:
    """The whole fake database. One instance per test."""

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self.auth_users: dict[str, dict[str, Any]] = {}
        self.lock = threading.RLock()
        self.auth = SimpleNamespace(admin=_AuthAdmin(self))

    def table(self, name: str) -> FakeQuery:
        return FakeQuery(self, name)

    # convenience for tests
    def rows(self, table: str, **eq: Any) -> list[dict[str, Any]]:
        return [r for r in self.tables.get(table, []) if all(r.get(k) == v for k, v in eq.items())]
