from __future__ import annotations

from collections.abc import Iterable

from tb_executor.blocker import DryRunBlocker, select_blocker
from tb_executor.guard import is_blockable_ip, is_blockable_network
from tb_executor.user_control import is_disableable_user, select_user_disabler


class ActionDispatcher:
    """Routes an approved action to the right real-world handler, each guarded.

    Supported action_types: ``block_ip`` (firewall) and ``disable_user`` (lock
    the account). Only actions listed in ``enabled_actions`` are carried out; the
    rest are reported as failed so nothing runs that the operator didn't opt into.
    """

    def __init__(
        self,
        *,
        enabled_actions: Iterable[str],
        dry_run: bool,
        firewall: str = "auto",
        allow_private: bool = False,
        ip_allowlist: Iterable[str] = (),
        user_allowlist: Iterable[str] = (),
        blocker=None,
        disabler=None,
    ) -> None:
        self.enabled = set(enabled_actions)
        self.allow_private = allow_private
        self.ip_allowlist = tuple(ip_allowlist)
        self.user_allowlist = tuple(user_allowlist)
        self.blocker = blocker if blocker is not None else select_blocker(dry_run=dry_run, firewall=firewall)
        self.disabler = disabler if disabler is not None else select_user_disabler(dry_run=dry_run)

    def mode(self) -> str:
        return "DRY-RUN" if isinstance(self.blocker, DryRunBlocker) else "LIVE"

    def handle(self, action_type: str, target: str) -> tuple[str, str]:
        """Carry out one action. Returns (result, detail); result is 'executed' or 'failed'."""
        if action_type not in self.enabled:
            return "failed", f"action '{action_type}' is not enabled on this executor"

        if action_type == "block_ip":
            ok, reason = is_blockable_ip(target or "", self.ip_allowlist, allow_private=self.allow_private)
            if not ok:
                return "failed", f"guard refused: {reason}"
            try:
                return "executed", self.blocker.block(target)
            except Exception as exc:
                return "failed", str(exc)

        if action_type == "block_range":
            ok, reason = is_blockable_network(target or "", self.ip_allowlist, allow_private=self.allow_private)
            if not ok:
                return "failed", f"guard refused: {reason}"
            try:
                return "executed", self.blocker.block(target)
            except Exception as exc:
                return "failed", str(exc)

        if action_type == "disable_user":
            ok, reason = is_disableable_user(target or "", self.user_allowlist)
            if not ok:
                return "failed", f"guard refused: {reason}"
            try:
                return "executed", self.disabler.disable(target)
            except Exception as exc:
                return "failed", str(exc)

        return "failed", f"unsupported action '{action_type}'"
