from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from typing import Any

log = logging.getLogger("threatbrain.spool")


class Spool:
    """Durable on-disk queue (JSON lines) for events the backend could not take.

    A host agent must not lose detections because the API is down for a minute.
    Items are replayed oldest-first; replay stops at the first failure so order
    is preserved and a dead backend is not hammered. Bounded so a long outage
    cannot fill the disk: the oldest items are dropped first.
    """

    def __init__(self, path: str, max_items: int = 2000) -> None:
        self.path, self.max_items = path, max_items
        self._lock = threading.Lock()

    def _read(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        items = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("dropping corrupt spool line")
        return items

    def _write(self, items: list[dict[str, Any]]) -> None:
        tmp = f"{self.path}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for item in items:
                fh.write(json.dumps(item, separators=(",", ":")) + "\n")
        os.replace(tmp, self.path)

    def append(self, payload: dict[str, Any]) -> None:
        with self._lock:
            items = self._read()
            items.append(payload)
            if len(items) > self.max_items:
                dropped = len(items) - self.max_items
                items = items[dropped:]
                log.error("spool full: dropped %d oldest event(s)", dropped)
            self._write(items)

    def __len__(self) -> int:
        with self._lock:
            return len(self._read())

    def replay(self, send: Callable[[dict[str, Any]], Any]) -> int:
        """Send queued items oldest-first; stop at the first failure. Returns sent count."""
        with self._lock:
            items = self._read()
        sent = 0
        for item in items:
            try:
                send(item)
            except Exception as exc:
                log.warning("spool replay paused: %s", exc)
                break
            sent += 1
        if sent:
            with self._lock:
                remaining = self._read()[sent:]
                self._write(remaining) if remaining else os.path.exists(self.path) and os.remove(self.path)
        return sent
