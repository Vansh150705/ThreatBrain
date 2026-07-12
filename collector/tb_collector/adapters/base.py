from __future__ import annotations

from abc import ABC, abstractmethod

from tb_collector.models import Detection


class SourceAdapter(ABC):
    """Turns raw log lines into aggregated Detections."""

    @abstractmethod
    def process_line(self, line: str, *, now: float) -> Detection | None:
        """Feed one log line; return a Detection when a threshold trips, else None."""
