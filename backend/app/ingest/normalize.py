"""Canonical keys inside ``raw_data`` so detection rules do not care which vendor sent the event.

Rules read a small set of canonical keys (parent_process, process_path, file_path, event_code,
target_image, granted_access, query, user_agent, url, bytes_out). Each adapter keeps the original
vendor record in ``raw_data``; this module adds the canonical keys next to it (never overwriting a
key the sender already supplied).
"""

from __future__ import annotations

import re
from typing import Any

# canonical key -> candidate dotted paths in vendor records (first present wins)
ALIASES: dict[str, tuple[str, ...]] = {
    "parent_process": ("data.win.eventdata.parentImage", "process.parent.executable", "process.parent.name",
                       "parentProcessName", "ParentImage", "data.parent_process"),
    "process_path": ("data.win.eventdata.image", "process.executable", "Image", "data.process_path"),
    "file_path": ("data.win.eventdata.targetFilename", "file.path", "syscheck.path", "TargetFilename", "data.file"),
    "event_code": ("data.win.system.eventID", "event.code", "EventID", "eventID"),
    "target_image": ("data.win.eventdata.targetImage", "TargetImage"),
    "source_image": ("data.win.eventdata.sourceImage", "SourceImage"),
    "granted_access": ("data.win.eventdata.grantedAccess", "GrantedAccess"),
    "query": ("data.win.eventdata.queryName", "dns.question.name", "QueryName", "query"),
    "user_agent": ("user_agent.original", "http.request.headers.user-agent", "data.user_agent", "userAgent",
                   "data.http_user_agent"),
    "url": ("url.original", "url.full", "data.url", "request.url", "requestURI", "data.http_url"),
    "bytes_out": ("source.bytes", "network.bytes_out", "bytes_sent", "data.bytes_out"),
    "direction": ("network.direction", "data.direction"),
    "logon_type": ("data.win.eventdata.logonType", "winlog.event_data.LogonType"),
    "authentication_package": ("data.win.eventdata.authenticationPackageName",),
    "logon_process": ("data.win.eventdata.logonProcessName",),
    "service_name": ("data.win.eventdata.serviceName",),
    "ticket_encryption_type": ("data.win.eventdata.ticketEncryptionType",),
    "share_name": ("data.win.eventdata.shareName",),
}
_PATH_KEYS = {"parent_process"}


def _lookup(record: dict[str, Any], dotted: str) -> Any:
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
        else:
            lowered = {str(k).lower(): v for k, v in cur.items()}
            if part.lower() not in lowered:
                return None
            cur = lowered[part.lower()]
    return cur


def _basename(v: str) -> str:
    return re.split(r"[\\/]", v.rstrip("\\/"))[-1]


def enrich_raw(raw: dict[str, Any]) -> dict[str, Any]:
    """Return ``raw`` plus canonical keys. Existing canonical keys are left untouched."""
    out = dict(raw)
    for key, paths in ALIASES.items():
        if key in out and out[key] not in (None, ""):
            continue
        for p in paths:
            v = _lookup(raw, p)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (dict, list)):
                continue
            out[key] = _basename(str(v)) if key in _PATH_KEYS else v
            break
    return out
