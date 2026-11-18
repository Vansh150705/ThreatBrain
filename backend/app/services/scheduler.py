"""Opt-in background scheduler for proactive threat hunting (HUNT_INTERVAL_MINUTES > 0)."""

from __future__ import annotations

import threading
from uuid import UUID

from app.agents.base import AgentInput
from app.agents.hunt import HuntAgent, HuntInput
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class HuntScheduler:
    """Runs the Hunt agent for every active organization every ``interval_minutes``."""

    def __init__(self, interval_minutes: int) -> None:
        self.interval = max(1, interval_minutes) * 60
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="hunt-scheduler", daemon=True)

    def start(self) -> None:
        self._thread.start()
        log.info("hunt_scheduler_started", interval_seconds=self.interval)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self.run_once()

    def run_once(self) -> int:
        """One sweep. Returns the number of organizations hunted."""
        hunted = 0
        try:
            orgs = (
                get_supabase_admin()
                .table("organizations")
                .select("id")
                .eq("status", "active")
                .is_("deleted_at", "null")
                .execute()
                .data
                or []
            )
        except Exception:
            log.exception("hunt_scheduler_org_list_failed")
            return 0
        for org in orgs:
            if self._stop.is_set():
                break
            try:
                HuntAgent().run(
                    AgentInput(
                        organization_id=UUID(str(org["id"])),
                        trigger_type="scheduled",
                        payload=HuntInput().model_dump(),
                    )
                )
                hunted += 1
            except Exception:
                log.exception("hunt_scheduler_org_failed", organization_id=str(org["id"]))
        return hunted
