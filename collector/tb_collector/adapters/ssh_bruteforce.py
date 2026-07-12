from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timezone

from tb_collector.adapters.base import SourceAdapter
from tb_collector.models import Detection

# Matches: "Failed password for [invalid user ]<user> from <ip> port ..."
_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


class AuthLogSSHBruteForce(SourceAdapter):
    """Detects SSH brute-force from auth.log 'Failed password' lines.

    Per source IP, keeps a sliding window of recent failures; when the count
    reaches ``threshold`` within ``window_seconds`` it emits one Detection and
    starts a ``cooldown_seconds`` quiet period so a single attack is one event.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
        kind: str = "ssh_bruteforce",
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.kind = kind
        self._events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._cooldown_until: dict[str, float] = {}

    def process_line(self, line: str, *, now: float) -> Detection | None:
        m = _FAILED_RE.search(line)
        if not m:
            return None
        ip = m.group("ip")
        user = m.group("user")

        if now < self._cooldown_until.get(ip, 0.0):
            return None

        window = self._events[ip]
        window.append((now, user))
        cutoff = now - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        if len(window) >= self.threshold:
            first_ts = window[0][0]
            self._cooldown_until[ip] = now + self.cooldown_seconds
            detection = Detection(
                kind=self.kind,
                source_ip=ip,
                username=user,
                count=len(window),
                window_seconds=self.window_seconds,
                first_seen=datetime.fromtimestamp(first_ts, tz=timezone.utc),
                last_seen=datetime.fromtimestamp(now, tz=timezone.utc),
                sample_lines=[line.strip()],
            )
            window.clear()
            return detection
        return None
