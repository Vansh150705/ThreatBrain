from __future__ import annotations

import time

from tb_executor.blocker import DryRunBlocker, select_blocker
from tb_executor.client import ExecutorClient
from tb_executor.config import ExecutorConfig
from tb_executor.guard import is_blockable_ip


def run(config: ExecutorConfig, *, client=None, blocker=None, iterations=None) -> None:
    """Poll for approved block_ip actions, guard, block, and report."""
    if client is None:
        client = ExecutorClient(config.base_url, config.email, config.password)
    if blocker is None:
        blocker = select_blocker(dry_run=config.dry_run, firewall=config.firewall)

    mode = "DRY-RUN" if isinstance(blocker, DryRunBlocker) else f"LIVE ({type(blocker).__name__})"
    print(f"[tb-executor] polling {config.base_url} every {config.poll_interval}s ({mode})")

    i = 0
    while iterations is None or i < iterations:
        try:
            pending = client.list_pending_blocks()
        except Exception as exc:
            print(f"[tb-executor] poll failed: {exc}")
            pending = []

        for item in pending:
            ip = item.get("target", "")
            ok, reason = is_blockable_ip(ip, config.allowlist, allow_private=config.allow_private)
            if not ok:
                print(f"[tb-executor] REFUSED {ip}: {reason}")
                client.report(item["id"], "failed", f"guard refused: {reason}")
                continue
            try:
                detail = blocker.block(ip)
                print(f"[tb-executor] BLOCKED {ip}: {detail}")
                client.report(item["id"], "executed", detail)
            except Exception as exc:
                print(f"[tb-executor] block failed for {ip}: {exc}")
                client.report(item["id"], "failed", str(exc))

        i += 1
        if iterations is None:
            time.sleep(config.poll_interval)
