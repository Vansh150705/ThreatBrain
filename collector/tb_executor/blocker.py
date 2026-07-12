from __future__ import annotations

import subprocess


class DryRunBlocker:
    """Records intended blocks without touching the firewall."""

    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block(self, ip: str) -> str:
        self.blocked.append(ip)
        return f"[dry-run] would block {ip}"


class IptablesBlocker:
    """Adds an iptables DROP rule for a source IP (idempotent). Linux only."""

    def __init__(self, chain: str = "INPUT") -> None:
        self.chain = chain

    def _rule_exists(self, ip: str) -> bool:
        result = subprocess.run(
            ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        return result.returncode == 0

    def block(self, ip: str) -> str:
        if self._rule_exists(ip):
            return f"already blocked {ip}"
        subprocess.run(
            ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        return f"iptables DROP added for {ip}"
