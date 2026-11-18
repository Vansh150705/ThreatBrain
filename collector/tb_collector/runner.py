from __future__ import annotations

import logging
import os
import threading
import time

from tb_collector.config import Config
from tb_collector.emitter import Emitter, EmitterError
from tb_collector.engine import DetectionEngine, default_detectors
from tb_collector.normalizer import detection_to_ingest_payload
from tb_collector.spool import Spool

log = logging.getLogger("threatbrain.collector")

SPOOL_REPLAY_SECONDS = 60


def _tail(path: str, *, follow: bool = True, poll: float = 0.5):
    """Yield new lines appended to a file, like ``tail -F``.

    Survives log rotation: if the path now points at a different file (rotated)
    or the file shrank (truncated), it is reopened and read from the start so no
    lines written after the rotation are missed.
    """
    fh = open(path, "r", encoding="utf-8", errors="replace")
    try:
        fh.seek(0, 2)  # start at end of file
        inode = os.fstat(fh.fileno()).st_ino
        while True:
            line = fh.readline()
            if line:
                yield line
                continue
            if not follow:
                return
            time.sleep(poll)
            try:
                st = os.stat(path)
            except FileNotFoundError:
                continue  # between rotate and recreate; keep waiting
            if st.st_ino != inode or st.st_size < fh.tell():
                log.info("log rotated or truncated, reopening: %s", path)
                fh.close()
                fh = open(path, "r", encoding="utf-8", errors="replace")
                inode = os.fstat(fh.fileno()).st_ino
    finally:
        fh.close()


def run(
    config: Config,
    *,
    http=None,
    follow: bool = True,
    engine: DetectionEngine | None = None,
    spool: Spool | None = None,
) -> None:
    """Tail the configured log(s), run the detection engine, and post detections.

    All watched files feed one shared engine, so cross-service correlation (e.g.
    distributed brute-force spanning SSH + web) works. Detector state is guarded
    by a lock since files are tailed on separate threads. Detections the backend
    cannot take right now are spooled to disk and replayed, never dropped.
    """
    if engine is None:
        engine = DetectionEngine(
            default_detectors(
                threshold=config.threshold,
                window=config.window_seconds,
                cooldown=config.cooldown_seconds,
            )
        )
    emitter = Emitter(
        config.base_url, config.email, config.password, http=http,
        api_key=config.api_key, async_ingest=config.async_ingest,
    )
    if spool is None:
        spool = Spool(config.spool_path, config.spool_max_items)
    lock = threading.Lock()
    stop = threading.Event()

    def handle(line: str) -> None:
        with lock:
            detections = engine.process_line(line, now=time.time())
        for detection in detections:
            payload = detection_to_ingest_payload(
                detection, collector_id=config.collector_id, asset_name=config.asset_name
            )
            log.info(
                "DETECTED %s (%s) from %s -> posting",
                detection.kind, detection.severity, detection.source_ip or "multiple",
            )
            try:
                result = emitter.post_event(payload)
                log.info("posted OK: %s", result.get("summary") or result.get("status") or {})
            except EmitterError as exc:
                if exc.transient:
                    spool.append(payload)
                    log.warning("backend unavailable, event spooled (%d queued): %s", len(spool), exc)
                else:
                    # a rejected payload/credential will not improve by waiting
                    log.error("event rejected, not retrying: %s", exc)
            except Exception:
                log.exception("unexpected error posting event")

    def watch(path: str) -> None:
        try:
            for line in _tail(path, follow=follow):
                handle(line)
        except FileNotFoundError:
            log.error("log not found, skipping: %s", path)

    def replay_loop() -> None:
        while not stop.wait(SPOOL_REPLAY_SECONDS):
            if len(spool):
                sent = spool.replay(emitter.post_event)
                if sent:
                    log.info("replayed %d spooled event(s)", sent)

    paths = config.effective_paths()
    log.info("watching %d log(s): %s", len(paths), ", ".join(paths))
    if len(spool):
        log.info("%d spooled event(s) from a previous run will be replayed", len(spool))
    threading.Thread(target=replay_loop, daemon=True, name="spool-replay").start()
    threads = [threading.Thread(target=watch, args=(p,), daemon=True) for p in paths]
    for t in threads:
        t.start()
    try:
        for t in threads:
            t.join()
    finally:
        stop.set()
