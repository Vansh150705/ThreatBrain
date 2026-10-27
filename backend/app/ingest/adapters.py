"""Adapters that turn common SIEM / telemetry formats into ``TriageInput``.

Each adapter accepts the parsed JSON body (or a raw string for CEF) and returns
a list of events. Adapters are defensive: unknown or malformed fields are
dropped rather than failing the whole batch, invalid IPs are discarded, and the
original record is kept (bounded) in ``raw_data`` for analysts and rule matching.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any, Callable

from app.agents.triage.schemas import TriageInput


class AdapterError(ValueError):
    """The payload cannot be interpreted in the requested format."""


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: Any) -> int | None:
    try:
        p = int(value)
    except (TypeError, ValueError):
        return None
    return p if 0 <= p <= 65535 else None


def _get(d: Any, path: str, default: Any = None) -> Any:
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        # Wazuh style "+0000" offsets
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _clip(value: Any, n: int = 500) -> str | None:
    return str(value)[:n] if value not in (None, "") else None


def _raw(record: Any) -> dict[str, Any]:
    """Keep the original record, but never let it blow the size cap."""
    if not isinstance(record, dict):
        return {"value": str(record)[:2000]}
    if len(json.dumps(record, default=str)) <= 50_000:
        return record
    return {"truncated": True, "keys": list(record)[:50]}


def _build(**kw: Any) -> TriageInput:
    kw["title"] = (kw.get("title") or "Security event")[:490]
    return TriageInput.model_validate({k: v for k, v in kw.items() if v is not None})


# ---------------------------------------------------------------- Wazuh ----
def _wazuh_one(a: dict[str, Any]) -> TriageInput:
    rule = a.get("rule") or {}
    data = a.get("data") or {}
    level = int(rule.get("level") or 0)
    sev_hint = "critical" if level >= 13 else "high" if level >= 10 else "medium" if level >= 7 else "low"
    raw = _raw(a)
    raw = {**raw, "severity_hint": sev_hint, "wazuh_rule_id": rule.get("id"), "wazuh_level": level}
    groups = rule.get("groups") or []
    if isinstance(groups, list) and any("authentication_fail" in g for g in groups):
        etype = "authentication.failed"
    else:
        etype = "wazuh." + (str(groups[0]).replace(" ", "_") if groups else "alert")
    return _build(
        title=_clip(rule.get("description"), 490) or "Wazuh alert",
        description=_clip(a.get("full_log"), 2000),
        source="siem",
        event_type=etype,
        source_ip=_ip(data.get("srcip") or _get(data, "win.eventdata.ipAddress")),
        destination_ip=_ip(data.get("dstip")),
        source_port=_port(data.get("srcport")),
        destination_port=_port(data.get("dstport")),
        username=_clip(data.get("dstuser") or data.get("srcuser") or _get(data, "win.eventdata.targetUserName"), 256),
        process_name=_clip(_get(data, "win.eventdata.image") or _get(a, "data.process"), 256),
        command_line=_clip(_get(data, "win.eventdata.commandLine") or data.get("command"), 8000),
        file_hash=_clip(_get(a, "syscheck.sha256_after") or _get(a, "syscheck.md5_after"), 64),
        asset_name=_clip(_get(a, "agent.name"), 256),
        occurred_at=_ts(a.get("timestamp")),
        raw_data=raw,
    )


def _wazuh(payload: Any) -> list[TriageInput]:
    items = payload if isinstance(payload, list) else [payload]
    return [_wazuh_one(i) for i in items if isinstance(i, dict)]


# ------------------------------------------------------------ Elastic ECS ----
def _ecs_one(d: dict[str, Any]) -> TriageInput:
    outcome = _get(d, "event.outcome")
    category = _get(d, "event.category")
    if isinstance(category, list):
        category = category[0] if category else None
    action = _get(d, "event.action")
    etype = ".".join(str(x) for x in (category, action) if x) or "ecs.event"
    if category == "authentication" and outcome == "failure":
        etype = "authentication.failed"
    sev = _get(d, "event.severity")
    raw = _raw(d)
    if isinstance(sev, (int, float)):
        raw = {**raw, "severity_hint": "critical" if sev >= 90 else "high" if sev >= 70 else "medium" if sev >= 40 else "low"}
    return _build(
        title=_clip(d.get("message") or _get(d, "rule.name") or action, 490) or "Elastic event",
        description=_clip(_get(d, "event.reason") or d.get("message"), 2000),
        source="siem",
        event_type=etype,
        source_ip=_ip(_get(d, "source.ip")),
        destination_ip=_ip(_get(d, "destination.ip")),
        source_port=_port(_get(d, "source.port")),
        destination_port=_port(_get(d, "destination.port")),
        username=_clip(_get(d, "user.name"), 256),
        process_name=_clip(_get(d, "process.name"), 256),
        command_line=_clip(_get(d, "process.command_line"), 8000),
        file_hash=_clip(_get(d, "file.hash.sha256") or _get(d, "file.hash.sha1") or _get(d, "file.hash.md5"), 64),
        asset_name=_clip(_get(d, "host.name"), 256),
        occurred_at=_ts(d.get("@timestamp")),
        raw_data=raw,
    )


def _ecs(payload: Any) -> list[TriageInput]:
    items = payload if isinstance(payload, list) else [payload]
    return [_ecs_one(i) for i in items if isinstance(i, dict)]


# ------------------------------------------------------------------ CEF ----
_CEF_HEADER = re.compile(r"^(?:.*?)CEF:(\d+)\|((?:\\.|[^|])*)\|((?:\\.|[^|])*)\|((?:\\.|[^|])*)\|((?:\\.|[^|])*)\|((?:\\.|[^|])*)\|((?:\\.|[^|])*)\|(.*)$", re.S)
_CEF_EXT = re.compile(r"(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|$)", re.S)


def _cef_one(line: str) -> TriageInput:
    m = _CEF_HEADER.match(line.strip())
    if not m:
        raise AdapterError("not a CEF record")
    _, vendor, product, _ver, sig_id, name, sev, ext_raw = m.groups()
    ext = {k: v.replace("\\=", "=").strip() for k, v in _CEF_EXT.findall(ext_raw)}
    try:
        sev_n = int(sev)
    except ValueError:
        sev_n = {"low": 3, "medium": 5, "high": 8, "very-high": 10}.get(sev.lower(), 0)
    hint = "critical" if sev_n >= 9 else "high" if sev_n >= 7 else "medium" if sev_n >= 4 else "low"
    return _build(
        title=_clip(name, 490) or "CEF event",
        description=_clip(ext.get("msg"), 2000),
        source="siem",
        event_type=f"cef.{re.sub(r'[^a-z0-9]+', '_', product.lower()).strip('_') or 'event'}",
        source_ip=_ip(ext.get("src")),
        destination_ip=_ip(ext.get("dst")),
        source_port=_port(ext.get("spt")),
        destination_port=_port(ext.get("dpt")),
        username=_clip(ext.get("suser") or ext.get("duser"), 256),
        process_name=_clip(ext.get("sproc") or ext.get("dproc"), 256),
        command_line=_clip(ext.get("cs1") if ext.get("cs1Label", "").lower() in ("commandline", "cmd") else None, 8000),
        file_hash=_clip(ext.get("fileHash"), 64),
        asset_name=_clip(ext.get("dvchost") or ext.get("dhost"), 256),
        raw_data={"cef": {"vendor": vendor, "product": product, "signature_id": sig_id, "severity": sev},
                  "extension": ext, "severity_hint": hint},
    )


def _cef(payload: Any) -> list[TriageInput]:
    if isinstance(payload, str):
        lines = [ln for ln in payload.splitlines() if ln.strip()]
    elif isinstance(payload, list):
        lines = [str(x) for x in payload]
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        lines = [str(x) for x in payload["events"]]
    else:
        raise AdapterError("CEF payload must be a string or a list of strings")
    return [_cef_one(ln) for ln in lines]


# ----------------------------------------------------------- CloudTrail ----
_CLOUD_READONLY = ("Get", "List", "Describe", "Head")


def _cloudtrail_one(r: dict[str, Any]) -> TriageInput:
    name = str(r.get("eventName") or "UnknownEvent")
    identity = r.get("userIdentity") or {}
    user = identity.get("userName") or identity.get("arn") or identity.get("principalId")
    err = r.get("errorCode")
    etype = f"cloud.{str(r.get('eventSource', 'aws')).split('.')[0]}.{name}"
    if name == "ConsoleLogin":
        etype = "authentication.failed" if _get(r, "responseElements.ConsoleLogin") == "Failure" else "cloud.console_login"
    title = f"AWS {name}" + (f" denied ({err})" if err else "") + (f" by {user}" if user else "")
    return _build(
        title=title[:490],
        description=_clip(r.get("errorMessage"), 2000),
        source="cloud_audit",
        event_type=etype,
        source_ip=_ip(r.get("sourceIPAddress")),
        username=_clip(user, 256),
        asset_name=_clip(r.get("recipientAccountId") or _get(r, "userIdentity.accountId"), 256),
        occurred_at=_ts(r.get("eventTime")),
        raw_data=_raw(r),
    )


def _cloudtrail(payload: Any) -> list[TriageInput]:
    if isinstance(payload, dict) and isinstance(payload.get("Records"), list):
        records = payload["Records"]
    elif isinstance(payload, list):
        records = payload
    else:
        records = [payload]
    out: list[TriageInput] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        # Read-only API noise is not worth an LLM call; keep denied reads (recon).
        name = str(rec.get("eventName") or "")
        if name.startswith(_CLOUD_READONLY) and not rec.get("errorCode"):
            continue
        out.append(_cloudtrail_one(rec))
    return out


# --------------------------------------------------------------- Splunk ----
_SPLUNK_KEYS = {
    "source_ip": ("src_ip", "src", "source_ip", "clientip", "client_ip"),
    "destination_ip": ("dest_ip", "dest", "dst_ip", "destination_ip"),
    "source_port": ("src_port",),
    "destination_port": ("dest_port", "dst_port", "dest_port"),
    "username": ("user", "username", "src_user", "dest_user"),
    "process_name": ("process", "process_name", "Image"),
    "command_line": ("command", "CommandLine", "process_command_line"),
    "asset_name": ("host", "dvc", "dest_host"),
}


def _splunk_one(item: dict[str, Any]) -> TriageInput:
    ev = item.get("event")
    if isinstance(ev, str):
        ev = {"message": ev}
    ev = ev if isinstance(ev, dict) else item
    merged = {**ev, **{k: v for k, v in item.items() if k in ("host", "source", "sourcetype")}}

    def pick(names: tuple[str, ...]) -> Any:
        for n in names:
            if merged.get(n) not in (None, ""):
                return merged[n]
        return None

    title = pick(("signature", "alert", "name", "message")) or f"Splunk event ({merged.get('sourcetype', 'unknown')})"
    return _build(
        title=_clip(title, 490),
        description=_clip(merged.get("message") or merged.get("_raw"), 2000),
        source="siem",
        event_type=_clip(merged.get("event_type") or f"splunk.{merged.get('sourcetype', 'event')}", 120),
        source_ip=_ip(pick(_SPLUNK_KEYS["source_ip"])),
        destination_ip=_ip(pick(_SPLUNK_KEYS["destination_ip"])),
        source_port=_port(pick(_SPLUNK_KEYS["source_port"])),
        destination_port=_port(pick(_SPLUNK_KEYS["destination_port"])),
        username=_clip(pick(_SPLUNK_KEYS["username"]), 256),
        process_name=_clip(pick(_SPLUNK_KEYS["process_name"]), 256),
        command_line=_clip(pick(_SPLUNK_KEYS["command_line"]), 8000),
        asset_name=_clip(pick(_SPLUNK_KEYS["asset_name"]), 256),
        occurred_at=_ts(item.get("time") or merged.get("_time")),
        raw_data=_raw(merged),
    )


def _splunk(payload: Any) -> list[TriageInput]:
    items = payload if isinstance(payload, list) else [payload]
    return [_splunk_one(i) for i in items if isinstance(i, dict)]


# -------------------------------------------------------------- generic ----
def _generic(payload: Any) -> list[TriageInput]:
    items = payload if isinstance(payload, list) else [payload]
    out = []
    for i in items:
        if not isinstance(i, dict):
            raise AdapterError("generic events must be JSON objects")
        out.append(TriageInput.model_validate(i.get("event", i)))
    return out


_ADAPTERS: dict[str, Callable[[Any], list[TriageInput]]] = {
    "generic": _generic,
    "wazuh": _wazuh,
    "ecs": _ecs,
    "cef": _cef,
    "cloudtrail": _cloudtrail,
    "splunk": _splunk,
}
SUPPORTED_FORMATS = tuple(_ADAPTERS)


def parse_payload(fmt: str, payload: Any, *, max_events: int = 50) -> list[TriageInput]:
    """Parse ``payload`` as ``fmt``; raises ``AdapterError`` on bad input."""
    adapter = _ADAPTERS.get(fmt)
    if adapter is None:
        raise AdapterError(f"unsupported format {fmt!r}; use one of {', '.join(SUPPORTED_FORMATS)}")
    try:
        events = adapter(payload)
    except AdapterError:
        raise
    except Exception as exc:  # pydantic ValidationError, bad types...
        raise AdapterError(f"could not parse {fmt} payload: {exc}") from exc
    if len(events) > max_events:
        raise AdapterError(f"too many events in one request ({len(events)} > {max_events})")
    return events
