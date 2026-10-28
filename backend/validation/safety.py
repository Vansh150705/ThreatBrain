"""Safety checks for adversary emulation (see docs/VALIDATION.md "Safety model").

The lab never executes attack commands. It emits *telemetry text* (log lines, event JSON). The only
network actions are HTTP posts of that text to a ThreatBrain API, and the target must be explicitly
allowed: loopback by default; anything else needs both an allow-listed host and LAB_AUTHORIZED=1.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class UnsafeTarget(Exception):
    pass


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        return [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
    except socket.gaierror as exc:
        raise UnsafeTarget(f"cannot resolve {host!r}") from exc


def assert_lab_target(url: str, *, env: dict[str, str] | None = None) -> None:
    """Refuse anything that is not explicitly an isolated lab target."""
    env = env if env is not None else dict(os.environ)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeTarget(f"not an http(s) URL: {url!r}")
    addrs = _resolve(parsed.hostname)
    if all(a.is_loopback for a in addrs):
        return
    allow = [n.strip() for n in env.get("LAB_ALLOWLIST", "").split(",") if n.strip()]
    if env.get("LAB_AUTHORIZED") != "1":
        raise UnsafeTarget("non-loopback target requires LAB_AUTHORIZED=1 (explicit authorization)")
    if not allow:
        raise UnsafeTarget("non-loopback target requires LAB_ALLOWLIST (comma-separated hosts/CIDRs)")
    for a in addrs:
        ok = False
        for entry in allow:
            try:
                ok = ok or a in ipaddress.ip_network(entry, strict=False)
            except ValueError:
                ok = ok or parsed.hostname == entry
        if not ok:
            raise UnsafeTarget(f"{a} is not in LAB_ALLOWLIST")
    for a in addrs:
        if a.is_global:
            raise UnsafeTarget(f"{a} is a public internet address; the lab only targets private/isolated ranges")


FORBIDDEN_PREFIXES = ("rm ", "dd ", "mkfs", "shred", "format ", "del ", "vssadmin", "wevtutil", "bcdedit", "net user")


def assert_text_only(command_text: str) -> str:
    """The lab only ever treats command strings as data. This guard makes that explicit: any code path
    that tried to hand a scenario command to a shell must go through here and is refused."""
    raise UnsafeTarget("scenario commands are telemetry text and are never executed")
