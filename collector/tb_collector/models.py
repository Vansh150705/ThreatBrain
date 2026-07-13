from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Detection:
    """One aggregated detection ready to be normalized and sent."""

    kind: str
    source_ip: str | None
    username: str | None
    count: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    sample_lines: list[str] = field(default_factory=list)
    severity: str = "high"                      # info|low|medium|high|critical (hint for triage)
    mitre: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)   # detector-specific context
