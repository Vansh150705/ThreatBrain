"""Stable fingerprints so repeat alerts fold into one threat."""

from __future__ import annotations

import hashlib
import re
from typing import Any

_NUM = re.compile(r"\d+")


def event_fingerprint(event: dict[str, Any], rule_ids: list[str] | None = None) -> str:
    """Hash of what makes two alerts "the same attack".

    Uses event type, source/destination, user, destination port and (when
    available) the matched rule ids. Free-text titles are digit-normalised so
    "12 failed logins" and "15 failed logins" still collapse together.
    """
    parts = [
        str(event.get("event_type") or "").lower(),
        str(event.get("source_ip") or "").lower(),
        str(event.get("destination_ip") or "").lower(),
        str(event.get("username") or "").lower(),
        str(event.get("destination_port") or ""),
        str(event.get("asset_name") or "").lower(),
        ",".join(sorted(rule_ids or [])),
    ]
    if not rule_ids and not event.get("source_ip"):
        parts.append(_NUM.sub("#", str(event.get("title") or "").lower()))
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:32]
