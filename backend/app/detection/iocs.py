"""Indicator-of-compromise extraction from free text."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_URL = re.compile(r"\bhttps?://[^\s'\"<>)\]]{4,200}", re.I)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I
)
_FILE_EXT = {"exe", "dll", "sh", "py", "txt", "log", "php", "js", "ps1", "bat", "conf", "json", "yaml", "yml"}


# Addresses that must never leave the organization in a third-party lookup.
# Documentation ranges (TEST-NET, used by labs and demos) are deliberately *not*
# listed: Python's ``is_private`` lumps them in with RFC 1918, which would make
# every lab attacker look "internal" and silently skip enrichment.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",  # RFC1918 + CGNAT
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128",
    )
)


def is_public_ip(value: str) -> bool:
    """True if ``value`` is safe to send to an external threat-intel service."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def extract_iocs(text: str, limit: int = 25) -> dict[str, list[str]]:
    """Return unique ips (valid), hashes, urls and domains found in ``text``."""
    text = text[:50_000]
    ips: list[str] = []
    for m in _IPV4.findall(text):
        try:
            ipaddress.ip_address(m)
        except ValueError:
            continue
        if m not in ips:
            ips.append(m)
    hashes = list(dict.fromkeys(h.lower() for h in _HASH.findall(text)))
    urls = list(dict.fromkeys(_URL.findall(text)))
    domains: list[str] = []
    for d in _DOMAIN.findall(text):
        d = d.lower()
        if d.rsplit(".", 1)[-1] in _FILE_EXT or d in domains:
            continue
        domains.append(d)
    return {
        "ips": ips[:limit],
        "hashes": hashes[:limit],
        "urls": urls[:limit],
        "domains": domains[:limit],
    }


def event_iocs(event: dict[str, Any]) -> dict[str, list[str]]:
    """IOCs for an event: explicit fields first, then anything in its text."""
    from app.detection.engine import build_view

    found = extract_iocs(build_view(event)["text"])
    for key in ("source_ip", "destination_ip"):
        v = event.get(key)
        if v and v not in found["ips"]:
            found["ips"].insert(0, v)
    fh = event.get("file_hash")
    if fh and fh.lower() not in found["hashes"]:
        found["hashes"].insert(0, fh.lower())
    return found
