from __future__ import annotations

import re
from datetime import datetime, timezone

from tb_collector.detectors import (
    DistributedBruteForce,
    Detector,
    LowAndSlow,
    PasswordSpraying,
    PerSourceGuessing,
    SuccessAfterFailure,
    UsernameEnumeration,
    WebScanning,
)
from tb_collector.models import Detection
from tb_collector.parsing import parse_auth_line, parse_web_request
from tb_collector.signatures import scan_line

# rsyslog collapses floods: "message repeated 43 times: [ Failed password ... ]"
_REPEAT = re.compile(r"message repeated (?P<n>\d+) times:\s*\[\s*(?P<inner>.*?)\s*\]\s*$")
_WEB_FIRST_IP = re.compile(r"^\s*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_ANY_IP = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


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
    """Runs both paths on each line: rate/behaviour detectors (auth events) and
    signature scanning (web exploits / scanner tools)."""

    def __init__(
        self,
        detectors: list[Detector] | None = None,
        sig_cooldown: int = 300,
        web_scanner: WebScanning | None = None,
    ) -> None:
        self.detectors = detectors if detectors is not None else default_detectors()
        self.sig_cooldown = sig_cooldown
        self._sig_cool: dict[tuple, float] = {}
        self.web_scanner = web_scanner if web_scanner is not None else WebScanning()

    def process_line(self, line: str, *, now: float) -> list[Detection]:
        results: list[Detection] = []

        # 1. Auth path: expand rsyslog compression, parse, run behaviour detectors.
        mult, inner = 1, line
        m = _REPEAT.search(line)
        if m:
            mult, inner = int(m.group("n")), m.group("inner")
        ev = parse_auth_line(inner, now=now)
        if ev is not None:
            if mult > 1:
                ev.count *= mult
            for d in self.detectors:
                det = d.feed(ev)
                if det is not None:
                    results.append(det)

        # 2. Signature path: attack payloads / scanner tools in the raw line.
        results.extend(self._scan_signatures(line, now))

        # 3. Behavioural web-scanning path: many URLs / errors from one IP.
        wr = parse_web_request(line, now=now)
        if wr is not None:
            det = self.web_scanner.feed_web(wr[0], wr[1], wr[2], now)
            if det is not None:
                results.append(det)
        return results

    def _scan_signatures(self, line: str, now: float) -> list[Detection]:
        hits = scan_line(line)
        if not hits:
            return []
        m = _WEB_FIRST_IP.match(line) or _ANY_IP.search(line)
        ip = m.group("ip") if m else None
        out: list[Detection] = []
        for name, kind, sev, mitre in hits:
            key = (ip or "?", kind)
            if now < self._sig_cool.get(key, 0.0):
                continue
            self._sig_cool[key] = now + self.sig_cooldown
            out.append(
                Detection(
                    kind=kind, source_ip=ip, username=None, count=1,
                    window_seconds=0, first_seen=_dt(now), last_seen=_dt(now),
                    sample_lines=[line.strip()[:300]], severity=sev, mitre=list(mitre),
                    extra={"service": "web", "signature": name},
                )
            )
        return out
