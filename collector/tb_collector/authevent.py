from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AuthEvent:
    """A single normalized authentication event, from any service/parser."""

    service: str            # "ssh" | "sudo" | "su" | "ftp" | "smtp" | "web" | "winrdp" | ...
    source_ip: str | None
    username: str | None
    outcome: str            # "fail" | "invalid" | "success"
    timestamp: float        # epoch seconds
    raw: str
    count: int = 1          # >1 when a log line was rsyslog-compressed
