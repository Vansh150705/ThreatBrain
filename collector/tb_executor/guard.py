from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def is_blockable_ip(
    ip: str,
    allowlist: Iterable[str] = (),
    *,
    allow_private: bool = False,
) -> tuple[bool, str]:
    """Return (blockable, reason). Refuses anything unsafe to firewall-drop.

    Loopback, link-local, multicast, unspecified, and allowlisted addresses are
    always refused. Private/RFC1918 addresses are refused unless ``allow_private``
    is set (needed in a LAN lab where the attacker is on a private IP; keep it
    off in production so an internal host is never dropped).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"not a valid IP: {ip!r}"
    if str(addr) in set(allowlist):
        return False, "IP is allowlisted"
    if addr.is_loopback:
        return False, "loopback address"
    if addr.is_link_local:
        return False, "link-local address"
    if addr.is_multicast:
        return False, "multicast address"
    if addr.is_unspecified:
        return False, "unspecified address"
    if addr.is_private and not allow_private:
        return False, "private/RFC1918 address (set allow_private for lab use)"
    return True, "ok"


def is_blockable_network(
    cidr: str,
    allowlist: Iterable[str] = (),
    *,
    allow_private: bool = False,
    min_prefix_v4: int = 16,
    min_prefix_v6: int = 32,
) -> tuple[bool, str]:
    """Return (blockable, reason) for a CIDR range (for blocking IP-rotating attackers).

    Refuses ranges that are too broad, special-use, private (unless allowed), or
    that contain an allowlisted IP — so a range block can't take out half the
    internet or your own hosts.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, f"not a valid CIDR range: {cidr!r}"
    if net.version == 4 and net.prefixlen < min_prefix_v4:
        return False, f"range too broad (/{net.prefixlen}); minimum is /{min_prefix_v4}"
    if net.version == 6 and net.prefixlen < min_prefix_v6:
        return False, f"range too broad (/{net.prefixlen}); minimum is /{min_prefix_v6}"
    if net.is_loopback or net.is_link_local or net.is_multicast or net.is_unspecified:
        return False, "special-use range"
    if net.is_private and not allow_private:
        return False, "private range (set allow_private for lab use)"
    for entry in allowlist:
        try:
            if ipaddress.ip_address(entry) in net:
                return False, f"range contains allowlisted IP {entry}"
        except ValueError:
            continue
    return True, "ok"
