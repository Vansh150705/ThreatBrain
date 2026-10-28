"""In-memory stand-in for the Supabase/PostgREST client used by the backend.

It is *schema aware*: table columns are parsed from ``database/migrations`` so a
query that selects, filters on or writes a column that does not exist fails here
the same way PostgREST would fail in production. It implements only the query
builder surface the backend uses (select/insert/upsert/update/delete, eq/neq/
in_/is_/gt(e)/lt(e)/contains/ilike, order/limit/range, ``not_``).
"""

from __future__ import annotations

import copy
import ipaddress
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

MIGRATIONS = Path(__file__).resolve().parents[2] / "database" / "migrations"

_NOT_COLUMN = {
    "constraint", "primary", "unique", "check", "foreign", "references", "on",
    "default", "not", "null", "create", "alter", "comment", "using", "with",
}


from postgrest.exceptions import APIError as _PostgrestAPIError  # noqa: E402


class APIError(_PostgrestAPIError):
    """A real postgrest APIError with the SQLSTATE code PostgREST would report (inferred from the message)."""

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__({"message": message, "code": code or _sqlstate(message), "hint": None, "details": None})


def _sqlstate(message: str) -> str:
    m = message.lower()
    if "invalid input" in m or "malformed array" in m:
        return "22P02"
    if "not-null" in m:
        return "23502"
    if "duplicate key" in m or "already been registered" in m:
        return "23505"
    if "column" in m and "does not exist" in m:
        return "42703"
    if "does not exist" in m:
        return "42P01"
    if "append-only" in m:
        return "P0001"
    return "XX000"


class Col:
    __slots__ = ("type", "not_null", "has_default", "default_expr")

    def __init__(self, type_: str, not_null: bool, has_default: bool, default_expr: str | None = None) -> None:
        self.type, self.not_null, self.has_default, self.default_expr = type_, not_null, has_default, default_expr


def _default_expr(text: str) -> str | None:
    m = re.search(r"\bDEFAULT\s+(.+?)(?:\s+(?:NOT\s+NULL|NULL|REFERENCES|CHECK|PRIMARY|UNIQUE)\b.*)?$", text, re.I)
    return m.group(1).strip().rstrip(",") if m else None


def _eval_default(expr: str | None) -> Any:
    """Evaluate the simple SQL DEFAULT expressions this schema uses (None = unsupported)."""
    if not expr:
        return None
    e = expr.strip()
    if re.match(r"^(NOW|CURRENT_TIMESTAMP)\(?\)?", e, re.I):
        return _now()
    m = re.match(r"^'(.*?)'(::[\w. ]+(\[\])?)?$", e, re.S)
    if m:
        lit, cast = m.group(1), (m.group(2) or "").lower()
        if "jsonb" in cast or "json" in cast:
            import json as _json
            return _json.loads(lit)
        return lit
    if re.match(r"^ARRAY\[\s*\]", e, re.I):
        return []
    m = re.match(r"^ARRAY\[(.*?)\](::[\w.\[\]]+)?$", e, re.I | re.S)
    if m:
        return re.findall(r"'([^']*)'", m.group(1))
    if re.match(r"^(TRUE|FALSE)$", e, re.I):
        return e.upper() == "TRUE"
    if re.match(r"^-?\d+$", e):
        return int(e)
    if re.match(r"^-?\d+\.\d+$", e):
        return float(e)
    if re.search(r"uuid_generate_v4|gen_random_uuid", e, re.I):
        return str(uuid.uuid4())
    m = re.search(r"generate_short_id\('(\w+)'\)", e, re.I)
    if m:
        return _short(m.group(1))
    return None


_COL_LINE = re.compile(r"^([a-z_][a-z0-9_]*)\s+((?:public\.|extensions\.)?[A-Za-z_][\w]*(?:\(\d+(?:,\d+)?\))?(?:\[\])?)(.*)$", re.I)


def _parse_col(line: str) -> tuple[str, Col] | None:
    m = _COL_LINE.match(line.strip().rstrip(","))
    if not m or m.group(1).lower() in _NOT_COLUMN:
        return None
    rest = m.group(3).upper()
    return m.group(1).lower(), Col(
        m.group(2).lower().replace("public.", "").replace("extensions.", ""),
        "NOT NULL" in rest or "PRIMARY KEY" in rest,
        "DEFAULT" in rest or "PRIMARY KEY" in rest,
        _default_expr(m.group(3)),
    )


def _parse_schema() -> tuple[dict[str, set[str]], dict[str, dict[str, Col]], dict[str, list[str]]]:
    schema: dict[str, set[str]] = {}
    cols_by_table: dict[str, dict[str, Col]] = {}
    enums: dict[str, list[str]] = {}
    for path in sorted(MIGRATIONS.glob("*.sql")):
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        for m in re.finditer(r"CREATE TYPE public\.(\w+) AS ENUM \((.*?)\)\s*;", sql, re.S | re.I):
            enums[m.group(1).lower()] = re.findall(r"'([^']*)'", m.group(2))
        for m in re.finditer(r"ALTER TYPE public\.(\w+) ADD VALUE IF NOT EXISTS '([^']*)'", sql, re.I):
            vals = enums.setdefault(m.group(1).lower(), [])
            if m.group(2) not in vals:
                vals.append(m.group(2))
        for m in re.finditer(
            r"CREATE TABLE(?: IF NOT EXISTS)?\s+public\.(\w+)\s*\((.*?)\n\);", sql, re.S | re.I
        ):
            table = m.group(1).lower()
            cols: set[str] = set()
            specs: dict[str, Col] = {}
            depth = 0
            last: str | None = None
            for line in m.group(2).split("\n"):
                stripped = line.strip()
                if depth == 0:
                    parsed = _parse_col(stripped)
                    if parsed:
                        cols.add(parsed[0])
                        specs[parsed[0]] = parsed[1]
                        last = parsed[0]
                    elif last and re.match(r"(DEFAULT|NOT\s+NULL|NULL|PRIMARY|UNIQUE|REFERENCES|CHECK|ON\s)", stripped, re.I):
                        up = stripped.upper()
                        sp = specs[last]
                        sp.not_null = sp.not_null or "NOT NULL" in up or "PRIMARY KEY" in up
                        sp.has_default = sp.has_default or up.startswith("DEFAULT") or " DEFAULT " in f" {up} "
                        if sp.default_expr is None:
                            sp.default_expr = _default_expr(stripped)
                    else:
                        tok = re.match(r"([a-z_][a-z0-9_]*)\s+\S", stripped, re.I)
                        if tok and tok.group(1).lower() not in _NOT_COLUMN:
                            cols.add(tok.group(1).lower())
                depth += line.count("(") - line.count(")")
            schema[table] = cols
            cols_by_table[table] = specs
        for m in re.finditer(r"ALTER TABLE\s+public\.(\w+)(.*?);", sql, re.S | re.I):
            table = m.group(1).lower()
            for part in re.finditer(r"ADD COLUMN(?: IF NOT EXISTS)?\s+([^,]+(?:\([^)]*\)[^,]*)*)", m.group(2), re.I):
                parsed = _parse_col(part.group(1).strip())
                if parsed:
                    schema.setdefault(table, set()).add(parsed[0])
                    cols_by_table.setdefault(table, {})[parsed[0]] = parsed[1]
    return schema, cols_by_table, enums


SCHEMA, COLUMNS, ENUMS = _parse_schema()


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
    "events": [("organization_id", "idempotency_key")],
    "replay_guard": [("key_id", "signature")],
    "correlation_hits": [("organization_id", "dedupe_key")],
    "detection_rule_versions": [("rule_id", "version")],
    "rule_overrides": [("organization_id", "rule_key")],
}
# partial unique indexes in the schema: (table, columns) -> row predicate
_PARTIAL_UNIQUE = {("detection_rules", ("organization_id", "rule_key")): lambda r: r.get("deleted_at") is None}
_APPEND_ONLY = {"audit_logs"}


_INT_RANGE = {"smallint": (-(2**15), 2**15 - 1), "integer": (-(2**31), 2**31 - 1), "int": (-(2**31), 2**31 - 1),
              "bigint": (-(2**63), 2**63 - 1)}


def _check_scalar(table: str, col: str, type_: str, value: Any) -> None:
    """Mimic PostgreSQL's input checks for the column types the schema uses."""
    if value is None or value == "now()":
        return

    def bad(msg: str) -> APIError:
        return APIError(f"{msg} (column {table}.{col}: {value!r})")

    t = type_.lower()
    if t in ENUMS:
        if value not in ENUMS[t]:
            raise bad(f'invalid input value for enum {t}')
    elif t == "uuid":
        try:
            uuid.UUID(str(value))
        except ValueError:
            raise bad("invalid input syntax for type uuid") from None
    elif t == "inet":
        try:
            ipaddress.ip_interface(str(value))
        except ValueError:
            raise bad("invalid input syntax for type inet") from None
    elif t in _INT_RANGE:
        try:
            n = int(value) if not isinstance(value, bool) else None
        except (TypeError, ValueError):
            n = None
        if n is None:
            raise bad(f"invalid input syntax for type {t}")
        lo, hi = _INT_RANGE[t]
        if not lo <= n <= hi:
            raise bad(f"value out of range for type {t}")
    elif t == "boolean":
        if not isinstance(value, bool):
            raise bad("invalid input syntax for type boolean")
    elif t in ("timestamptz", "timestamp"):
        try:
            datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            raise bad("invalid input syntax for type timestamp") from None
    elif t in ("text", "citext") or t.startswith("varchar"):
        if isinstance(value, (dict, list)):
            raise bad("cannot store a JSON structure in a text column")


def _check_value(table: str, col: str, type_: str, value: Any) -> None:
    if value is None:
        return
    if type_.endswith("[]"):
        if not isinstance(value, list):
            raise APIError(f"malformed array literal (column {table}.{col}: {value!r})")
        for item in value:
            _check_scalar(table, col, type_[:-2], item)
    else:
        _check_scalar(table, col, type_, value)


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
        self.ignore_dups = False
        self.not_ = _Not(self)

    # ---- builders ------------------------------------------------------
    def select(self, cols: str = "*", count: str | None = None) -> "FakeQuery":
        self.cols, self.count_mode = cols, count
        return self

    def insert(self, payload: Any) -> "FakeQuery":
        self.op, self.payload = "insert", payload
        return self

    def upsert(self, payload: Any, on_conflict: str | None = None, ignore_duplicates: bool = False, **_: Any) -> "FakeQuery":
        self.op, self.payload, self.on_conflict = "upsert", payload, on_conflict
        self.ignore_dups = ignore_duplicates
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
        self._check_filter_value(col, val)
        self._add_filter(col, lambda v: _norm(v) == _norm(val))
        return self

    def neq(self, col: str, val: Any) -> "FakeQuery":
        self._add_filter(col, lambda v: _norm(v) != _norm(val))
        return self

    def in_(self, col: str, vals: list[Any]) -> "FakeQuery":
        self._check_filter_value(col, list(vals))
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
    def _validate_row(self, row: dict[str, Any], *, insert: bool) -> None:
        specs = COLUMNS.get(self.table, {})
        for col, value in row.items():
            spec = specs.get(col)
            if spec is None:
                continue
            if value is None and spec.not_null and not spec.has_default:
                raise APIError(f'null value in column "{col}" of relation "{self.table}" violates not-null constraint')
            _check_value(self.table, col, spec.type, value)
        if insert:
            defaults = _DEFAULTS.get(self.table, {})
            for col, spec in specs.items():
                if spec.not_null and not spec.has_default and col not in row and col not in defaults and col != "id":
                    raise APIError(f'null value in column "{col}" of relation "{self.table}" violates not-null constraint')

    def _check_filter_value(self, col: str, value: Any) -> None:
        base = col.split("->>")[0]
        spec = COLUMNS.get(self.table, {}).get(base)
        if spec is None or "->" in col:
            return
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            if isinstance(v, str) and v in ("null", "true", "false"):
                continue
            _check_scalar(self.table, col, spec.type.replace("[]", ""), v)

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
                self._validate_row(item, insert=True)
                res = self._insert_one(rows, item)
                if res is not None:
                    out.append(res)
            return FakeResult(copy.deepcopy(out))

        self._check_columns([c for c, _ in self.filters])
        if self.cols != "*":
            self._check_columns([c.strip() for c in self.cols.split(",") if c.strip()])
        matched = [r for r in rows if all(p(_resolve(r, c)) for c, p in self.filters)]

        if self.op == "update":
            if self.table in _APPEND_ONLY:
                raise APIError("audit_logs is append-only")
            self._check_columns(list(self.payload.keys()))
            self._validate_row(self.payload, insert=False)
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

    def _insert_one(self, rows: list[dict[str, Any]], item: dict[str, Any]) -> dict[str, Any] | None:
        new: dict[str, Any] = {}
        for k, spec in COLUMNS.get(self.table, {}).items():
            if spec.has_default:
                new[k] = _eval_default(spec.default_expr)
        for k, dv in _DEFAULTS.get(self.table, {}).items():
            if k not in new or new[k] is None:
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
        for (tbl, pkey), pred in _PARTIAL_UNIQUE.items():
            if tbl == self.table and pred(new):
                for existing in rows:
                    if pred(existing) and all(_norm(existing.get(c)) == _norm(new.get(c)) for c in pkey):
                        raise APIError(f"duplicate key value violates unique constraint {pkey}")
        for key in keys:
            if any(new.get(c) is None for c in key):
                continue  # NULLs never conflict in a unique index
            for existing in rows:
                if all(_norm(existing.get(c)) == _norm(new.get(c)) for c in key):
                    if self.op == "upsert":
                        if self.ignore_dups:
                            return None
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

    def rpc(self, name: str, params: dict[str, Any] | None = None) -> "FakeRpc":
        return FakeRpc(self, name, params or {})

    # convenience for tests
    def rows(self, table: str, **eq: Any) -> list[dict[str, Any]]:
        return [r for r in self.tables.get(table, []) if all(r.get(k) == v for k, v in eq.items())]


class FakeRpc:
    """The two PL/pgSQL functions the backend calls, ported line for line."""

    def __init__(self, db: FakeSupabase, name: str, params: dict[str, Any]) -> None:
        self.db, self.name, self.params = db, name, params

    def execute(self) -> FakeResult:
        with self.db.lock:
            fn = getattr(self, f"_{self.name}", None)
            if fn is None:
                raise APIError(f"function public.{self.name} does not exist")
            return fn(**self.params)

    def _claim_jobs(self, p_worker: str, p_limit: int = 1, p_lease_seconds: int = 300, p_queues: list[str] | None = None) -> FakeResult:
        rows = self.db.tables.setdefault("jobs", [])
        now = datetime.now(UTC)

        def ts(v: Any) -> datetime:
            return datetime.fromisoformat(str(v).replace("Z", "+00:00"))

        for r in rows:
            if r["status"] == "running" and r["locked_until"] and ts(r["locked_until"]) < now and r["attempts"] >= r["max_attempts"]:
                r.update(status="dead", locked_by=None, locked_until=None, finished_at=_now(),
                         last_error=r.get("last_error") or "lease expired; attempts exhausted")
        eligible = [
            r for r in rows
            if ((r["status"] == "queued" and ts(r["run_after"]) <= now)
                or (r["status"] == "running" and r["locked_until"] and ts(r["locked_until"]) < now and r["attempts"] < r["max_attempts"]))
            and (p_queues is None or r["queue"] in p_queues)
        ]
        eligible.sort(key=lambda r: (-r["priority"], ts(r["run_after"])))
        out = []
        for r in eligible[: max(p_limit, 0)]:
            r.update(status="running", attempts=r["attempts"] + 1, locked_by=p_worker,
                     locked_until=(now + timedelta(seconds=p_lease_seconds)).isoformat(),
                     started_at=r.get("started_at") or _now())
            out.append(copy.deepcopy(r))
        return FakeResult(out)

    def _purge_expired(self, **_: Any) -> FakeResult:
        return FakeResult({"events_unlinked": 0})
