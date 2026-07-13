from __future__ import annotations

import re

from tb_collector.detectors import (
    DistributedBruteForce,
    Detector,
    LowAndSlow,
    PasswordSpraying,
    PerSourceGuessing,
    SuccessAfterFailure,
    UsernameEnumeration,
)
from tb_collector.models import Detection
from tb_collector.parsing import parse_auth_line

# rsyslog collapses floods: "message repeated 43 times: [ Failed password ... ]"
_REPEAT = re.compile(r"message repeated (?P<n>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]\s*$")


def default_detectors(
    *, threshold: int = 10, window: int = 60, cooldown: int = 300, low_slow_threshold: int = 15
) -> list[Detector]:
    return [
        PerSourceGuessing(threshold=threshold, window=window, cooldown=cooldown),
        SuccessAfterFailure(),
        PasswordSpraying(),
        UsernameEnumeration(),
        DistributedBruteForce(),
        LowAndSlow(threshold=low_slow_threshold),
    ]


class DetectionEngine:
    """Parses each log line, expands rsyslog compression, and runs all detectors."""

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors if detectors is not None else default_detectors()

    def process_line(self, line: str, *, now: float) -> list[Detection]:
        mult, inner = 1, line
        m = _REPEAT.search(line)
        if m:
            mult, inner = int(m.group("n")), m.group("inner")

        ev = parse_auth_line(inner, now=now)
        if ev is None:
            return []
        if mult > 1:
            ev.count *= mult

        results: list[Detection] = []
        for d in self.detectors:
            det = d.feed(ev)
            if det is not None:
                results.append(det)
        return results
