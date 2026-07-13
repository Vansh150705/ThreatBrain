from __future__ import annotations

from typing import Any

from tb_collector.models import Detection


def _describe(d: Detection) -> tuple[str, str, str]:
    """Return (title, event_type, description) tuned so Triage escalates correctly."""
    ip = d.source_ip or "multiple sources"
    user = d.username or "unknown"
    svc = d.extra.get("service", "auth")
    k = d.kind

    if k == "brute_force":
        return (
            f"{svc.upper()} brute-force from {ip}",
            "authentication.brute_force",
            f"{d.count} failed {svc} logins from {ip} within {d.window_seconds}s "
            f"(sustained single-source brute-force).",
        )
    if k == "brute_force_success":
        return (
            f"Account compromise: successful {svc} login from {ip} after {d.count} failures",
            "authentication.brute_force_success",
            f"CRITICAL: {ip} logged in successfully as '{user}' after {d.count} failed attempts "
            f"— a likely successful brute-force / account takeover.",
        )
    if k == "password_spraying":
        n = len(d.extra.get("usernames", [])) or d.count
        return (
            f"Password spraying from {ip}",
            "authentication.password_spraying",
            f"{ip} attempted {svc} logins against {n} distinct accounts within "
            f"{d.window_seconds}s (password spraying).",
        )
    if k == "username_enumeration":
        n = len(d.extra.get("invalid_users", [])) or d.count
        return (
            f"Username enumeration from {ip}",
            "authentication.username_enumeration",
            f"{ip} probed {n} distinct non-existent {svc} usernames within "
            f"{d.window_seconds}s (account enumeration).",
        )
    if k == "distributed_brute_force":
        n = len(d.extra.get("source_ips", [])) or d.count
        return (
            f"Distributed brute-force against '{user}'",
            "authentication.distributed_brute_force",
            f"{n} distinct source IPs failed {svc} logins against '{user}' within "
            f"{d.window_seconds}s (distributed / botnet brute-force).",
        )
    if k == "brute_force_slow":
        return (
            f"Low-and-slow brute-force from {ip}",
            "authentication.brute_force_slow",
            f"{d.count} failed {svc} logins from {ip} over an extended window "
            f"(low-and-slow brute-force designed to evade rate limits).",
        )
    return (
        f"Suspicious auth activity from {ip}",
        "authentication.suspicious",
        d.sample_lines[0] if d.sample_lines else "Suspicious authentication activity.",
    )


def detection_to_ingest_payload(
    d: Detection,
    *,
    collector_id: str,
    asset_name: str | None = None,
) -> dict[str, Any]:
    """Turn a Detection into the backend /ingest/event request body."""
    title, event_type, description = _describe(d)
    raw_data: dict[str, Any] = {
        "detection_kind": d.kind,
        "severity_hint": d.severity,
        "mitre": d.mitre,
        "count": d.count,
        "window_seconds": d.window_seconds,
        "first_seen": d.first_seen.isoformat(),
        "last_seen": d.last_seen.isoformat(),
        "sample_lines": d.sample_lines[:5],
    }
    raw_data.update(d.extra)

    return {
        "source_system": f"tb-collector/{d.extra.get('service', 'auth')}",
        "collector_id": collector_id,
        "event": {
            "title": title[:490],
            "description": description,
            "source": "authentication",
            "event_type": event_type,
            "source_ip": d.source_ip,
            "username": d.username,
            "asset_name": asset_name,
            "raw_data": raw_data,
        },
    }
