from __future__ import annotations

import platform
import re
import subprocess
from collections.abc import Iterable

# Accounts we never auto-disable (would lock out admins / break the system).
_PROTECTED = {
    "root", "administrator", "admin", "system", "daemon", "guest",
    "sshd", "postfix", "dovecot", "www-data", "nobody",
}
_VALID_USER = re.compile(r"^[\w.\-\\$]+$")


def is_disableable_user(user: str, allowlist: Iterable[str] = ()) -> tuple[bool, str]:
    """Return (disableable, reason). Refuses protected / allowlisted / odd names."""
    if not user or not user.strip():
        return False, "empty username"
    u = user.strip()
    if u.lower() in _PROTECTED:
        return False, f"protected account '{u}'"
    if u.lower() in {a.lower() for a in allowlist}:
        return False, "user is allowlisted"
    if not _VALID_USER.match(u):
        return False, f"unusual username {u!r}"
    return True, "ok"


class DryRunUserDisabler:
    """Records intended account disables without touching the system."""

    def __init__(self) -> None:
        self.disabled: list[str] = []

    def disable(self, user: str) -> str:
        self.disabled.append(user)
        return f"[dry-run] would disable account {user}"


class LinuxUserDisabler:
    """Locks a local account (reversible with `usermod -U`)."""

    def __init__(self, runner=None) -> None:
        self._run = runner or (lambda args: subprocess.run(args, capture_output=True))

    def disable(self, user: str) -> str:
        result = self._run(["usermod", "-L", user])
        if result.returncode != 0:
            raise RuntimeError(f"usermod -L failed (rc={result.returncode})")
        return f"locked account {user} (usermod -L)"


class WindowsUserDisabler:
    """Disables a local account (reversible with `net user <u> /active:yes`)."""

    def __init__(self, runner=None) -> None:
        self._run = runner or (lambda args: subprocess.run(args, capture_output=True))

    def disable(self, user: str) -> str:
        result = self._run(["net", "user", user, "/active:no"])
        if result.returncode != 0:
            raise RuntimeError(f"net user disable failed (rc={result.returncode})")
        return f"disabled account {user} (net user /active:no)"


def select_user_disabler(*, dry_run: bool, system: str | None = None):
    if dry_run:
        return DryRunUserDisabler()
    system = system or platform.system()
    return WindowsUserDisabler() if system == "Windows" else LinuxUserDisabler()
