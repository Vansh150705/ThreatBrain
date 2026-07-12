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
