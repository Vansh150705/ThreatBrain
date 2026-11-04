"""Turn a normalised event into behavioural observations (no I/O).

Only fields that are already part of the normalised event are used. Command lines and payload bodies never reach a
baseline: a baseline is a statistical summary of *which* hosts, networks, processes and volumes an entity uses.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.ingest.identity import canonical_host, canonical_user


@dataclass(frozen=True)
class Feature:
    name: str
    kind: str                 # cat | hour | num | bucket | breadth
    family: str               # features in one family are one signal (max, not sum)
    weight: float             # how suspicious a deviation in this feature is on its own, 0-1
    code: str                 # detection id when this family dominates an alert
    title: str
    techniques: tuple[str, ...]
    entity: str               # user | host
    min_obs: int = 8          # observations of THIS feature needed before novelty means anything (0 = first-ever use is itself the signal)


FEATURES: dict[str, Feature] = {f.name: f for f in (
    Feature("auth.source_net", "cat", "auth_location", 0.75, "TB-UEBA-001", "Sign-in from a network this account has not used before", ("T1078",), "user"),
    Feature("auth.hour", "hour", "auth_time", 0.55, "TB-UEBA-002", "Sign-in at an hour outside this account's normal pattern", ("T1078",), "user"),
    Feature("auth.host", "cat", "auth_location", 0.60, "TB-UEBA-003", "Account signed in to a system it does not normally use", ("T1078", "T1021"), "user"),
    Feature("auth.breadth", "breadth", "auth_breadth", 0.80, "TB-UEBA-003", "Account reached an unusually large number of systems in an hour", ("T1021", "T1078"), "user"),
    Feature("priv.action", "cat", "privilege", 0.90, "TB-UEBA-004", "Privileged or administrative action this identity has not performed before", ("T1098", "T1078"), "user", 0),
    Feature("cloud.action", "cat", "privilege", 0.50, "TB-UEBA-004", "Cloud or identity API call this identity has not made before", ("T1078",), "user"),
    Feature("resource.access", "cat", "data_access", 0.60, "TB-UEBA-005", "Access to a resource this identity has not used before", ("T1530", "T1213"), "user", 0),
    Feature("proc.name", "cat", "process", 0.45, "TB-UEBA-006", "Process never seen on this host", ("T1059",), "host"),
    Feature("proc.pair", "cat", "process", 0.55, "TB-UEBA-006", "Unusual parent/child process relationship on this host", ("T1059",), "host"),
    Feature("proc.exec_path", "cat", "process", 0.80, "TB-UEBA-006", "Program run from a user-writable location for the first time on this host", ("T1204", "T1059"), "host", 0),
    Feature("net.dest", "cat", "net_dest", 0.45, "TB-UEBA-007", "Connection to a destination network this host has not contacted before", ("T1071",), "host"),
    Feature("net.port", "cat", "net_dest", 0.40, "TB-UEBA-007", "Connection on a port this host has not used before", ("T1571",), "host"),
    Feature("net.bytes_flow", "num", "volume", 0.70, "TB-UEBA-008", "Unusually large single transfer for this host", ("T1041", "T1048"), "host"),
    Feature("net.bytes_out_hour", "bucket", "volume", 0.85, "TB-UEBA-008", "Unusual outbound data volume for this host in an hour", ("T1041", "T1048"), "host"),
)}
FAMILY_CODE = {f.family: f.code for f in FEATURES.values()}

_SUCCESS_LOGIN = ("authentication.success", "cloud.console_login", "identity.login", "identity.okta.login", "identity.signin")
_WRITABLE = re.compile(r"(/tmp/|/dev/shm/|/var/tmp/|\\appdata\\|\\temp\\|\\users\\public\\|\\downloads\\|\\programdata\\|\\perflogs\\)", re.I)
_WRITABLE_CLASS = (("tmp", re.compile(r"/tmp/|\\temp\\", re.I)), ("shm", re.compile(r"/dev/shm/", re.I)),
                   ("appdata", re.compile(r"\\appdata\\", re.I)), ("public", re.compile(r"\\users\\public\\", re.I)),
                   ("downloads", re.compile(r"\\downloads\\", re.I)), ("programdata", re.compile(r"\\programdata\\", re.I)))
_PRIV_ACTION = re.compile(
    r"^(create|delete|attach|detach|put|update|add|remove|set|enable|disable|modify|assume|grant|revoke|reset)"
    r"(user|accesskey|role|policy|userpolicy|rolepolicy|grouppolicy|loginprofile|group|trail|bucketpolicy|keypolicy|"
    r"permissionset|federation|samlprovider|oidcprovider|virtualmfadevice|rolewithsaml|rolewithwebidentity|accountpasswordpolicy)?$",
    re.I)
_PRIV_SOURCE = re.compile(r"^(iam|sts|organizations|kms|cloudtrail|config|guardduty|securityhub|sso|identitystore)\b", re.I)
_PRIV_STRICT = re.compile(r"(accesskey|loginprofile|rolepolicy|userpolicy|grouppolicy|attach\w*policy|createuser|createrole|"
                          r"putbucketpolicy|stoplogging|deletetrail|updatetrail|disable\w*|schedulekeydeletion|assumerole)", re.I)
_DATA_READ = re.compile(r"^(get|list|describe|read|download|copy|select|query|scan|export|batchget|head)", re.I)
_RESOURCE_KEYS = ("requestParameters.bucketName", "bucketName", "bucket", "requestParameters.secretId", "secretId",
                  "requestParameters.name", "resource", "resource_name", "share_name", "file_path", "table", "object")
_ACTION_KEYS = ("eventName", "event_name", "eventname", "action", "operation")
_BYTES_KEYS = ("bytes_out", "bytes_sent", "sentbyte", "bytes")


@dataclass(frozen=True)
class Obs:
    etype: str
    eid: str
    feature: str
    ts: float
    key: str = ""
    value: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)


def event_time(event: dict[str, Any]) -> float:
    for k in ("observed_at", "occurred_at", "created_at"):
        v = event.get(k)
        if not v:
            continue
        if isinstance(v, datetime):
            dt = v
        else:
            try:
                dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            except ValueError:
                continue
        return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()
    return datetime.now(UTC).timestamp()


_INTERNAL = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128"))


def is_internal(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """RFC1918 / loopback / link-local / CGNAT / ULA. Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) count
    as EXTERNAL: they are what test data and lab scenarios use to stand in for the internet."""
    return any(addr in n for n in _INTERNAL if n.version == addr.version)


def net_key(ip: str) -> tuple[str, bool] | None:
    """(network, is_external): /24 for IPv4, /48 for IPv6. Individual addresses churn too much to baseline."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
    return str(net), not is_internal(addr)


def _first(raw: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        cur: Any = raw
        for part in k.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                break
        if cur not in (None, "", [], {}):
            return cur
    return None


def _proc(name: str) -> str:
    n = re.split(r"[\\/]", str(name).strip())[-1].lower()
    return n[:-4] if n.endswith(".exe") else n


def extract(event: dict[str, Any]) -> list[Obs]:
    et = str(event.get("event_type") or "").lower()
    raw = event.get("raw_data") or {}
    ts = event_time(event)
    user = canonical_user(event.get("username"))
    host = canonical_host(event.get("asset_name"))
    src = event.get("source_ip")
    out: list[Obs] = []

    if user and et.startswith(_SUCCESS_LOGIN):
        if src and (nk := net_key(src)):
            out.append(Obs("user", user, "auth.source_net", ts, nk[0], meta={"external": nk[1]}))
        out.append(Obs("user", user, "auth.hour", ts, str(int(ts % 86400 // 3600))))
        if host and host != user:
            out.append(Obs("user", user, "auth.host", ts, host))
            out.append(Obs("user", user, "auth.breadth", ts, host))

    action = _first(raw, _ACTION_KEYS)
    if user and action and et.startswith(("cloud.", "audit.", "identity.", "iam.", "database.", "file.")):
        action = str(action)[:120]
        source = str(_first(raw, ("eventSource", "event_source", "service")) or "")
        is_priv = bool(_PRIV_STRICT.search(action) or (_PRIV_SOURCE.match(source) and _PRIV_ACTION.match(action)))
        out.append(Obs("user", user, "priv.action" if is_priv else "cloud.action", ts, action.lower()))
        resource = _first(raw, _RESOURCE_KEYS)
        if resource and _DATA_READ.match(action):
            out.append(Obs("user", user, "resource.access", ts, str(resource)[:200].lower(), meta={"action": action}))
    elif user and et.startswith("identity.") and not et.startswith(_SUCCESS_LOGIN):
        out.append(Obs("user", user, "cloud.action", ts, et))

    if et.startswith("process.") and event.get("process_name") and host:
        name = _proc(event["process_name"])
        if name:
            out.append(Obs("host", host, "proc.name", ts, name))
            parent = raw.get("parent_process")
            if parent:
                out.append(Obs("host", host, "proc.pair", ts, f"{_proc(parent)}>{name}"))
            path = str(raw.get("process_path") or "")
            if path and _WRITABLE.search(path):
                klass = next((c for c, rx in _WRITABLE_CLASS if rx.search(path)), "writable")
                out.append(Obs("host", host, "proc.exec_path", ts, f"{klass}:{name}"))

    if et.startswith("network.") and event.get("destination_ip"):
        hid = host or (f"ip:{src}" if src else None)
        if hid:
            dk = net_key(event["destination_ip"])
            if dk:
                out.append(Obs("host", hid, "net.dest", ts, dk[0], meta={"external": dk[1]}))
            if event.get("destination_port"):
                out.append(Obs("host", hid, "net.port", ts, str(event["destination_port"])))
            sent = _first(raw, _BYTES_KEYS)
            try:
                sent = float(sent) if sent is not None else 0.0
            except (TypeError, ValueError):
                sent = 0.0
            if sent > 0 and dk and dk[1]:           # only data leaving the network is volume of interest
                out.append(Obs("host", hid, "net.bytes_flow", ts, value=sent, meta={"dest": dk[0]}))
                out.append(Obs("host", hid, "net.bytes_out_hour", ts, value=sent, meta={"dest": dk[0]}))
    return out
