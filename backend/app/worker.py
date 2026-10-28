"""Standalone worker entrypoint: ``python -m app.worker`` (scale by running more replicas)."""

from __future__ import annotations

import signal
import threading

from app.core.logging import get_logger, setup_logging
from app.services.worker import Worker

setup_logging()
log = get_logger(__name__)


def main() -> None:
    worker = Worker(role="worker")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    worker.start()
    stop.wait()
    log.info("worker_shutdown_requested")
    worker.stop()


if __name__ == "__main__":
    main()
