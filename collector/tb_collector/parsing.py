from __future__ import annotations

import re

from tb_collector.authevent import AuthEvent

# One canonical line per attempt is chosen per service to avoid double-counting
# (sshd emits several lines per failure; we key off "Failed password"/"Accepted").
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

_SSH_ACCEPTED = re.compile(rf"Accepted (?:password|publickey|keyboard-interactive/\S+) for (?P<user>\S+) from {_IP}")
_SSH_FAILED = re.compile(rf"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from {_IP}")
_SUDO_FAIL = re.compile(r"(?:sudo:[^\n]*authentication failure|pam_unix\(sudo:auth\): authentication failure)")
_SU_FAIL = re.compile(r"(?:FAILED su for (?P<user1>\S+)|pam_unix\(su:auth\): authentication failure)")
_USER_KV = re.compile(r"user=(?P<user>\S+)")


def parse_auth_line(line: str, *, now: float) -> AuthEvent | None:
    """Turn one raw log line into an AuthEvent, or None if it isn't auth-relevant."""
    m = _SSH_ACCEPTED.search(line)
    if m:
        return AuthEvent("ssh", m.group("ip"), m.group("user"), "success", now, line.strip())

    m = _SSH_FAILED.search(line)
    if m:
        outcome = "invalid" if m.group("invalid") else "fail"
        return AuthEvent("ssh", m.group("ip"), m.group("user"), outcome, now, line.strip())

    if _SUDO_FAIL.search(line):
        um = _USER_KV.search(line)
        return AuthEvent("sudo", None, um.group("user") if um else None, "fail", now, line.strip())

    m = _SU_FAIL.search(line)
    if m:
        um = _USER_KV.search(line)
        user = m.groupdict().get("user1") or (um.group("user") if um else None)
        return AuthEvent("su", None, user, "fail", now, line.strip())

    return None
