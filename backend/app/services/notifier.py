"""Outbound notifications (Discord webhook). Best effort: never raises."""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Overridable in tests (httpx.MockTransport).
_transport: httpx.BaseTransport | None = None

_COLORS = {"critical": 0xDC2626, "high": 0xEA580C, "medium": 0xCA8A04, "low": 0x2563EB, "info": 0x6B7280}
NOTIFY_SEVERITIES = {"high", "critical"}


def notify_incident(incident: dict[str, Any], *, event: str = "created") -> bool:
    """Post a Discord embed for a high/critical incident. Returns True if sent."""
    settings = get_settings()
    severity = str(incident.get("severity") or "info")
    if severity not in NOTIFY_SEVERITIES:
        return False
    if not settings.discord_webhook_ok:
        # Webhook unset, or not a discord.com URL: refuse to POST to arbitrary hosts (SSRF).
        if settings.DISCORD_WEBHOOK_URL:
            log.warning("discord_webhook_rejected", reason="not a discord.com webhook URL")
        return False

    embed = {
        "title": f"[{severity.upper()}] {incident.get('short_id', 'incident')} {event}",
        "description": str(incident.get("title") or "")[:300],
        "color": _COLORS.get(severity, _COLORS["info"]),
        "fields": [
            {"name": "Priority", "value": str(incident.get("priority", "n/a")), "inline": True},
            {"name": "Threats", "value": str(incident.get("threat_count", 0)), "inline": True},
            {"name": "Source IPs", "value": ", ".join(map(str, (incident.get("source_ips") or [])[:5])) or "n/a"},
        ],
    }
    try:
        with httpx.Client(timeout=8.0, transport=_transport) as client:
            resp = client.post(
                settings.DISCORD_WEBHOOK_URL,
                json={"username": "ThreatBrain", "embeds": [embed]},
            )
        if resp.status_code >= 300:
            log.warning("discord_notify_failed", status=resp.status_code)
            return False
        return True
    except Exception as exc:
        log.warning("discord_notify_error", error_type=type(exc).__name__)
        return False
