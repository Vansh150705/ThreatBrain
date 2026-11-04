"""Canonical spellings of identities so one actor/host is one entity.

The same person shows up as ``CORP\\Alice``, ``alice`` and ``ALICE``; the same server as ``WEB-01.corp.local``,
``web-01`` and ``WEB-01``. Correlation groups, behavioural baselines and de-duplication all key on these fields,
so un-normalised spellings silently split an attack across entities (a trivial and common evasion, usually accidental).

Conservative by design: UPNs (``alice@corp.com``) keep their domain, FQDNs collapse only to the first label, and the
sender's original spelling is preserved by the caller in ``raw_data`` so nothing is lost.
"""

from __future__ import annotations

import ipaddress
import re

_QUOTES = " \t\r\n"
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9_-]{0,62})$")


def canonical_user(value: str | None) -> str | None:
    if value is None:
        return None
    v = str(value).strip(_QUOTES)
    if not v:
        return None
    if "\\" in v:
        v = v.rsplit("\\", 1)[-1]
    return v.lower()[:256] or None


def canonical_host(value: str | None) -> str | None:
    if value is None:
        return None
    v = str(value).strip(_QUOTES).rstrip(".").lower()
    if not v:
        return None
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    if "." in v:
        first, _, rest = v.partition(".")
        if _LABEL.match(first) and not rest.replace(".", "").isdigit():
            return first
    return v[:256]
