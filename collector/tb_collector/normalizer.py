from __future__ import annotations

from typing import Any

from tb_collector.models import Detection


def detection_to_ingest_payload(
    d: Detection,
    *,
    collector_id: str,
    asset_name: str | None = None,
) -> dict[str, Any]:
    """Turn a Detection into the backend /ingest/event request body."""
    user = d.username or "unknown"
    return {
        "source_system": f"tb-collector/{d.kind}",
        "collector_id": collector_id,
        "event": {
            "title": f"SSH brute-force from {d.source_ip}",
            "description": (
                f"{d.count} failed SSH logins for user '{user}' "
                f"within {d.window_seconds}s."
            ),
            "source": "authentication",
            "event_type": "authentication.brute_force",
            "source_ip": d.source_ip,
            "username": d.username,
            "asset_name": asset_name,
            "raw_data": {
                "failed_count": d.count,
                "window_seconds": d.window_seconds,
                "first_seen": d.first_seen.isoformat(),
                "last_seen": d.last_seen.isoformat(),
                "sample_lines": d.sample_lines[:5],
            },
        },
    }
