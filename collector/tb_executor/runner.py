from __future__ import annotations

import logging
import time

from tb_executor.actions import ActionDispatcher
from tb_executor.client import ExecutorClient
from tb_executor.config import ExecutorConfig

log = logging.getLogger("threatbrain.executor")


def run(config: ExecutorConfig, *, client=None, dispatcher=None, iterations=None) -> None:
    """Poll for approved actions, guard + carry each out, and report the result.

    Resilient by design: a failed poll or report never kills the loop. If a
    report cannot be delivered the action stays 'approved/unreported' on the
    server and is picked up again next poll; the handlers are idempotent
    (an existing firewall rule is detected), so re-running is safe.
    """
    if client is None:
        client = ExecutorClient(
            config.base_url, config.email, config.password, api_key=config.api_key
        )
    if dispatcher is None:
        dispatcher = ActionDispatcher(
            enabled_actions=config.enabled_actions,
            dry_run=config.dry_run,
            firewall=config.firewall,
            allow_private=config.allow_private,
            ip_allowlist=config.allowlist,
            user_allowlist=config.user_allowlist,
        )

    log.info(
        "polling %s every %ss (%s) · actions: %s",
        config.base_url, config.poll_interval, dispatcher.mode(), ", ".join(sorted(dispatcher.enabled)),
    )

    i = 0
    while iterations is None or i < iterations:
        try:
            pending = client.list_pending_actions()
        except Exception as exc:
            log.warning("poll failed: %s", exc)
            pending = []

        for item in pending:
            action_type = item.get("action_type", "")
            target = item.get("target", "")
            result, detail = dispatcher.handle(action_type, target)
            label = "EXECUTED" if result == "executed" else "REFUSED"
            log.info("%s %s on %s: %s", label, action_type, target, detail)
            try:
                client.report(item["id"], result, detail)
            except Exception as exc:
                log.error("could not report result for %s (will retry next poll): %s", item.get("id"), exc)

        i += 1
        if iterations is None:
            time.sleep(config.poll_interval)
