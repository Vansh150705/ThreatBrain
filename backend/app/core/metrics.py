"""Minimal in-process Prometheus metrics (no extra dependency). Text exposition format 0.0.4.

Per-process counters/histograms are exposed by each API replica; queue/worker gauges are computed from the
database at scrape time so they are correct no matter which replica is scraped. Label values must come from
small closed sets (route templates, rule ids, status classes) to bound cardinality; never put user input in a label.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from collections.abc import Iterable

_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)
_lock = threading.Lock()


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(name: str, labels: tuple[tuple[str, str], ...], value: float) -> str:
    if labels:
        inner = ",".join(f'{k}="{_esc(v)}"' for k, v in labels)
        return f"{name}{{{inner}}} {value}"
    return f"{name} {value}"


class Counter:
    def __init__(self, name: str, help_: str) -> None:
        self.name, self.help = name, help_
        self.values: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with _lock:
            self.values[key] += amount

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} counter"
        with _lock:
            items = list(self.values.items())
        for key, v in sorted(items):
            yield _fmt(self.name, key, v)


class Histogram:
    def __init__(self, name: str, help_: str, buckets: tuple[float, ...] = _BUCKETS) -> None:
        self.name, self.help, self.buckets = name, help_, buckets
        self.counts: dict[tuple[tuple[str, str], ...], list[float]] = {}
        self.sums: dict[tuple[tuple[str, str], ...], float] = defaultdict(float)

    def observe(self, seconds: float, **labels: str) -> None:
        key = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with _lock:
            row = self.counts.setdefault(key, [0.0] * (len(self.buckets) + 1))
            for i, b in enumerate(self.buckets):
                if seconds <= b:
                    row[i] += 1
            row[-1] += 1
            self.sums[key] += seconds

    def render(self) -> Iterable[str]:
        yield f"# HELP {self.name} {self.help}"
        yield f"# TYPE {self.name} histogram"
        with _lock:
            items = [(k, list(v), self.sums[k]) for k, v in self.counts.items()]
        for key, row, total in sorted(items):
            for b, c in zip(self.buckets, row, strict=False):
                yield _fmt(f"{self.name}_bucket", (*key, ("le", str(b))), c)
            yield _fmt(f"{self.name}_bucket", (*key, ("le", "+Inf")), row[-1])
            yield _fmt(f"{self.name}_sum", key, round(total, 6))
            yield _fmt(f"{self.name}_count", key, row[-1])


http_requests = Counter("tb_http_requests_total", "HTTP requests by route template and status class")
http_duration = Histogram("tb_http_request_duration_seconds", "HTTP request latency by route template")
events_ingested = Counter("tb_events_ingested_total", "Events accepted into the event store, by outcome (accepted|duplicate)")
detections = Counter("tb_detection_hits_total", "Detection hits by rule id and kind (rule|correlation)")
jobs_finished = Counter("tb_jobs_finished_total", "Queue jobs finished by kind and result (succeeded|retried|dead)")
job_duration = Histogram("tb_job_duration_seconds", "Queue job execution time by kind")
llm_calls = Counter("tb_llm_calls_total", "LLM calls by provider and result (ok|error)")
llm_tokens = Counter("tb_llm_tokens_total", "LLM tokens by provider and type (prompt|completion)")
llm_latency = Histogram("tb_llm_call_duration_seconds", "LLM call latency by provider")
pipeline_runs = Counter("tb_pipeline_runs_total", "Agent pipeline runs by outcome (completed|failed|degraded)")
auth_failures = Counter("tb_auth_failures_total", "Rejected authentications by reason")

REGISTRY = [http_requests, http_duration, events_ingested, detections, jobs_finished, job_duration,
            llm_calls, llm_tokens, llm_latency, pipeline_runs, auth_failures]


def render(extra_gauges: dict[str, tuple[str, dict[tuple[tuple[str, str], ...], float]]] | None = None) -> str:
    lines: list[str] = []
    for m in REGISTRY:
        lines.extend(m.render())
    for name, (help_, series) in (extra_gauges or {}).items():
        lines += [f"# HELP {name} {help_}", f"# TYPE {name} gauge"]
        lines += [_fmt(name, k, v) for k, v in sorted(series.items())]
    return "\n".join(lines) + "\n"
