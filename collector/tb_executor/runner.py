from __future__ import annotations

import time

from tb_executor.actions import ActionDispatcher
from tb_executor.client import ExecutorClient
from tb_executor.config import ExecutorConfig


def run(config: ExecutorConfig, *, client=None, dispatcher=None, iterations=None) -> None:
    """Poll for approved actions, guard + carry each out, and report the result."""
    if client is None:
        client = ExecutorClient(config.base_url, config.email, config.password)
    if dispatcher is None:
        dispatcher = ActionDispatcher(
            enabled_actions=config.enabled_actions,
            dry_run=config.dry_run,
            firewall=config.firewall,
            allow_private=config.allow_private,
            ip_allowlist=config.allowlist,
            user_allowlist=config.user_allowlist,
        )

    print(
        f"[tb-executor] polling {config.base_url} every {config.poll_interval}s "
        f"({dispatcher.mode()}) · actions: {', '.join(sorted(dispatcher.enabled))}"
    )

    i = 0
    while iterations is None or i < iterations:
        try:
            pending = client.list_pending_actions()
        except Exception as exc:
            print(f"[tb-executor] poll failed: {exc}")
            pending = []

        for item in pending:
            action_type = item.get("action_type", "")
            target = item.get("target", "")
            result, detail = dispatcher.handle(action_type, target)
            label = "EXECUTED" if result == "executed" else "REFUSED"
            print(f"[tb-executor] {label} {action_type} on {target}: {detail}")
            client.report(item["id"], result, detail)

        i += 1
        if iterations is None:
            time.sleep(config.poll_interval)
