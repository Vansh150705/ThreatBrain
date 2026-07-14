from __future__ import annotations

import platform
import subprocess


class DryRunBlocker:
    """Records intended blocks without touching any firewall."""

    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block(self, ip: str) -> str:
        self.blocked.append(ip)
        return f"[dry-run] would block {ip}"


class IptablesBlocker:
    """Adds an iptables DROP rule for a source IP (idempotent). Linux only."""

    def __init__(self, chain: str = "INPUT", runner=None) -> None:
        self.chain = chain
        self._run = runner or (lambda args: subprocess.run(args, capture_output=True))

    def _rule_exists(self, ip: str) -> bool:
        return self._run(["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"]).returncode == 0

    def block(self, ip: str) -> str:
        if self._rule_exists(ip):
            return f"already blocked {ip}"
        result = self._run(["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"])
        if result.returncode != 0:
            raise RuntimeError(f"iptables failed (rc={result.returncode})")
        return f"iptables DROP added for {ip}"


class WindowsFirewallBlocker:
    """Adds a Windows Firewall inbound block rule for a source IP (idempotent)."""

    def __init__(self, runner=None) -> None:
        self._run = runner or (lambda args: subprocess.run(args, capture_output=True))

    def _rule_name(self, ip: str) -> str:
        return f"ThreatBrain block {ip}"

    def _rule_exists(self, ip: str) -> bool:
        # netsh returns rc=0 when a matching rule exists, non-zero otherwise.
        return self._run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={self._rule_name(ip)}"]
        ).returncode == 0

    def block(self, ip: str) -> str:
        if self._rule_exists(ip):
            return f"already blocked {ip}"
        result = self._run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self._rule_name(ip)}", "dir=in", "action=block", f"remoteip={ip}",
            ]
        )
        if result.returncode != 0:
            raise RuntimeError(f"netsh firewall add failed (rc={result.returncode})")
        return f"Windows Firewall block rule added for {ip}"


def select_blocker(*, dry_run: bool, firewall: str = "auto", system: str | None = None):
    """Pick the right blocker for the platform / config.

    firewall: "auto" (detect OS), "iptables", "windows", or "dry-run".
    """
    if dry_run or firewall == "dry-run":
        return DryRunBlocker()
    system = system or platform.system()
    if firewall == "windows" or (firewall == "auto" and system == "Windows"):
        return WindowsFirewallBlocker()
    return IptablesBlocker()
