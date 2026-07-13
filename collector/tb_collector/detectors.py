from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone

from tb_collector.authevent import AuthEvent
from tb_collector.models import Detection

FAILISH = ("fail", "invalid")


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


class Detector:
    """Consumes AuthEvents; returns a Detection when its technique is seen."""

    def feed(self, ev: AuthEvent) -> Detection | None:  # pragma: no cover - interface
        return None


class PerSourceGuessing(Detector):
    """T1110.001 — one source IP fails N times within a short window."""

    def __init__(self, threshold: int = 10, window: int = 60, cooldown: int = 300) -> None:
        self.threshold, self.window, self.cooldown = threshold, window, cooldown
        self._win: dict[str, deque] = defaultdict(deque)
        self._cool: dict[str, float] = {}

    def feed(self, ev):
        if ev.outcome not in FAILISH or not ev.source_ip:
            return None
        ip, now = ev.source_ip, ev.timestamp
        if now < self._cool.get(ip, 0.0):
            return None
        w = self._win[ip]
        w.append((now, ev.count))
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        total = sum(c for _, c in w)
        if total >= self.threshold:
            first = w[0][0]
            self._cool[ip] = now + self.cooldown
            w.clear()
            return Detection(
                kind="brute_force", source_ip=ip, username=ev.username, count=total,
                window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                sample_lines=[ev.raw], severity="high", mitre=["T1110.001"],
                extra={"service": ev.service},
            )
        return None


class SuccessAfterFailure(Detector):
    """T1110 -> T1078 — a success from a source with recent failures = likely breach."""

    def __init__(self, min_fails: int = 5, window: int = 600) -> None:
        self.min_fails, self.window = min_fails, window
        self._fails: dict[str, deque] = defaultdict(deque)

    def feed(self, ev):
        if not ev.source_ip:
            return None
        ip, now = ev.source_ip, ev.timestamp
        w = self._fails[ip]
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        if ev.outcome in FAILISH:
            w.append((now, ev.count))
            return None
        if ev.outcome == "success":
            total = sum(c for _, c in w)
            if total >= self.min_fails:
                first = w[0][0] if w else now
                w.clear()
                return Detection(
                    kind="brute_force_success", source_ip=ip, username=ev.username, count=total,
                    window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                    sample_lines=[ev.raw], severity="critical", mitre=["T1110", "T1078"],
                    extra={"service": ev.service, "compromised_user": ev.username, "prior_failures": total},
                )
        return None


class PasswordSpraying(Detector):
    """T1110.003 — one source IP fails against many distinct usernames."""

    def __init__(self, distinct_users: int = 5, window: int = 300, cooldown: int = 600) -> None:
        self.n, self.window, self.cooldown = distinct_users, window, cooldown
        self._seen: dict[str, deque] = defaultdict(deque)
        self._cool: dict[str, float] = {}

    def feed(self, ev):
        if ev.outcome not in FAILISH or not ev.source_ip or not ev.username:
            return None
        ip, now = ev.source_ip, ev.timestamp
        if now < self._cool.get(ip, 0.0):
            return None
        w = self._seen[ip]
        w.append((now, ev.username))
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        users = {u for _, u in w}
        if len(users) >= self.n:
            first = w[0][0]
            self._cool[ip] = now + self.cooldown
            w.clear()
            return Detection(
                kind="password_spraying", source_ip=ip, username=None, count=len(users),
                window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                sample_lines=[ev.raw], severity="high", mitre=["T1110.003"],
                extra={"service": ev.service, "usernames": sorted(users)},
            )
        return None


class UsernameEnumeration(Detector):
    """T1087 — one source IP probes many distinct non-existent (invalid) usernames."""

    def __init__(self, distinct_invalid: int = 8, window: int = 300, cooldown: int = 600) -> None:
        self.n, self.window, self.cooldown = distinct_invalid, window, cooldown
        self._seen: dict[str, deque] = defaultdict(deque)
        self._cool: dict[str, float] = {}

    def feed(self, ev):
        if ev.outcome != "invalid" or not ev.source_ip or not ev.username:
            return None
        ip, now = ev.source_ip, ev.timestamp
        if now < self._cool.get(ip, 0.0):
            return None
        w = self._seen[ip]
        w.append((now, ev.username))
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        users = {u for _, u in w}
        if len(users) >= self.n:
            first = w[0][0]
            self._cool[ip] = now + self.cooldown
            w.clear()
            return Detection(
                kind="username_enumeration", source_ip=ip, username=None, count=len(users),
                window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                sample_lines=[ev.raw], severity="medium", mitre=["T1087"],
                extra={"service": ev.service, "invalid_users": sorted(users)},
            )
        return None


class DistributedBruteForce(Detector):
    """T1110.001 — one target account is failed by many distinct source IPs."""

    def __init__(self, distinct_ips: int = 8, window: int = 300, cooldown: int = 600) -> None:
        self.n, self.window, self.cooldown = distinct_ips, window, cooldown
        self._seen: dict[str, deque] = defaultdict(deque)
        self._cool: dict[str, float] = {}

    def feed(self, ev):
        if ev.outcome not in FAILISH or not ev.username or not ev.source_ip:
            return None
        user, now = ev.username, ev.timestamp
        if now < self._cool.get(user, 0.0):
            return None
        w = self._seen[user]
        w.append((now, ev.source_ip))
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        ips = {i for _, i in w}
        if len(ips) >= self.n:
            first = w[0][0]
            self._cool[user] = now + self.cooldown
            w.clear()
            return Detection(
                kind="distributed_brute_force", source_ip=ev.source_ip, username=user, count=len(ips),
                window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                sample_lines=[ev.raw], severity="high", mitre=["T1110.001"],
                extra={"service": ev.service, "target_user": user, "source_ips": sorted(ips)},
            )
        return None


class LowAndSlow(Detector):
    """T1110.001 — a source IP reaches a modest count over a long (hours) window."""

    def __init__(self, threshold: int = 15, window: int = 86400, cooldown: int = 86400) -> None:
        self.threshold, self.window, self.cooldown = threshold, window, cooldown
        self._win: dict[str, deque] = defaultdict(deque)
        self._cool: dict[str, float] = {}

    def feed(self, ev):
        if ev.outcome not in FAILISH or not ev.source_ip:
            return None
        ip, now = ev.source_ip, ev.timestamp
        if now < self._cool.get(ip, 0.0):
            return None
        w = self._win[ip]
        w.append((now, ev.count))
        cut = now - self.window
        while w and w[0][0] < cut:
            w.popleft()
        total = sum(c for _, c in w)
        if total >= self.threshold:
            first = w[0][0]
            self._cool[ip] = now + self.cooldown
            w.clear()
            return Detection(
                kind="brute_force_slow", source_ip=ip, username=ev.username, count=total,
                window_seconds=self.window, first_seen=_dt(first), last_seen=_dt(now),
                sample_lines=[ev.raw], severity="high", mitre=["T1110.001"],
                extra={"service": ev.service, "window": "long"},
            )
        return None
