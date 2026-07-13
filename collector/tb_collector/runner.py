from __future__ import annotations

import threading
import time

from tb_collector.config import Config
from tb_collector.emitter import Emitter
from tb_collector.engine import DetectionEngine, default_detectors
from tb_collector.normalizer import detection_to_ingest_payload


def _tail(path: str, *, follow: bool = True):
    """Yield new lines appended to a file (like ``tail -f``)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # start at end of file
        while True:
            line = fh.readline()
            if line:
                yield line
            elif follow:
                time.sleep(0.5)
            else:
                return


def run(config: Config, *, http=None, follow: bool = True, engine: DetectionEngine | None = None) -> None:
    """Tail the configured log(s), run the detection engine, and post detections.

    All watched files feed one shared engine, so cross-service correlation (e.g.
    distributed brute-force spanning SSH + web) works. Detector state is guarded
    by a lock since files are tailed on separate threads.
    """
    if engine is None:
        engine = DetectionEngine(
            default_detectors(
                threshold=config.threshold,
                window=config.window_seconds,
                cooldown=config.cooldown_seconds,
            )
        )
    emitter = Emitter(config.base_url, config.email, config.password, http=http)
    lock = threading.Lock()

    def handle(line: str) -> None:
        with lock:
            detections = engine.process_line(line, now=time.time())
        for detection in detections:
            payload = detection_to_ingest_payload(
                detection, collector_id=config.collector_id, asset_name=config.asset_name
            )
            print(
                f"[tb-collector] DETECTED {detection.kind} ({detection.severity}) "
                f"from {detection.source_ip or 'multiple'} -> posting"
            )
            try:
                result = emitter.post_event(payload)
                print(f"[tb-collector] posted OK: {result.get('summary', {})}")
            except Exception as exc:  # keep running through transient failures
                print(f"[tb-collector] post failed: {exc}")

    def watch(path: str) -> None:
        try:
            for line in _tail(path, follow=follow):
                handle(line)
        except FileNotFoundError:
            print(f"[tb-collector] log not found, skipping: {path}")

    paths = config.effective_paths()
    print(f"[tb-collector] watching {len(paths)} log(s): {', '.join(paths)} · 6 detectors")
    threads = [threading.Thread(target=watch, args=(p,), daemon=True) for p in paths]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
