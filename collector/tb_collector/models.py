from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Detection:
    """One aggregated security detection ready to be normalized and sent."""

    kind: str
    source_ip: str
    username: str | None
    count: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    sample_lines: list[str] = field(default_factory=list)
