from __future__ import annotations

import re

from tb_collector.authevent import AuthEvent

# Each parser turns one raw log line into an AuthEvent (or None). A canonical
# line is chosen per service to avoid double-counting the several lines sshd/PAM
# emit per attempt. Add a protocol = add one parser to PARSERS.

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_USER_KV = re.compile(r"user=(?P<user>\S+)")

# --- SSH (sshd) ---
# `from (?P<ip>\S+)` captures IPv4, IPv6, or a hostname (the executor's guard
# validates it before any block). Failed matches password / publickey / keyboard-
# interactive so key-based and interactive brute force are counted too.
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/\S+) for (?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/\S+) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)


def _p_ssh(line: str, now: float) -> AuthEvent | None:
    m = _SSH_ACCEPTED.search(line)
    if m:
        return AuthEvent("ssh", m.group("ip"), m.group("user"), "success", now, line.strip())
    m = _SSH_FAILED.search(line)
    if m:
        outcome = "invalid" if m.group("invalid") else "fail"
        return AuthEvent("ssh", m.group("ip"), m.group("user"), outcome, now, line.strip())
    return None


# --- local sudo / su ---
_SUDO_FAIL = re.compile(r"(?:sudo:[^\n]*authentication failure|pam_unix\(sudo:auth\): authentication failure)")
_SU_FAIL = re.compile(r"(?:FAILED su for (?P<user1>\S+)|pam_unix\(su:auth\): authentication failure)")


def _p_sudo_su(line: str, now: float) -> AuthEvent | None:
    if _SUDO_FAIL.search(line):
        um = _USER_KV.search(line)
        return AuthEvent("sudo", None, um.group("user") if um else None, "fail", now, line.strip())
    m = _SU_FAIL.search(line)
    if m:
        um = _USER_KV.search(line)
        user = m.groupdict().get("user1") or (um.group("user") if um else None)
        return AuthEvent("su", None, user, "fail", now, line.strip())
    return None


# --- generic PAM (ftp/imap/pop3/vpn/etc.), excluding services handled above ---
_PAM = re.compile(r"pam_unix\((?P<svc>[\w-]+):auth\): authentication failure")
_RHOST = re.compile(rf"rhost={_IP}")
_PAM_EXCLUDE = {"sshd", "sudo", "su"}
_PAM_SVC_NORM = {"vsftpd": "ftp", "proftpd": "ftp", "dovecot": "imap", "pure-ftpd": "ftp"}


def _p_pam(line: str, now: float) -> AuthEvent | None:
    m = _PAM.search(line)
    if not m:
        return None
    svc = m.group("svc")
    if svc in _PAM_EXCLUDE:
        return None
    rm = _RHOST.search(line)
    um = _USER_KV.search(line)
    return AuthEvent(
        _PAM_SVC_NORM.get(svc, svc),
        rm.group("ip") if rm else None,
        um.group("user") if um else None,
        "fail",
        now,
        line.strip(),
    )


# --- FTP (vsftpd/proftpd own log) ---
_FTP_OK = re.compile(rf'OK LOGIN: Client "?{_IP}"?')
_FTP_FAIL = re.compile(rf'FAIL LOGIN: Client "?{_IP}"?')


def _p_ftp(line: str, now: float) -> AuthEvent | None:
    m = _FTP_OK.search(line)
    if m:
        return AuthEvent("ftp", m.group("ip"), None, "success", now, line.strip())
    m = _FTP_FAIL.search(line)
    if m:
        return AuthEvent("ftp", m.group("ip"), None, "fail", now, line.strip())
    return None


# --- mail: postfix SASL + dovecot ---
_POSTFIX_SASL = re.compile(rf"warning:[^\[]*\[{_IP}\]:\s*SASL\s+\S*\s*authentication failed")
_RIP = re.compile(rf"rip={_IP}")
_DOVE_USER = re.compile(r"user=<?(?P<user>[^>,\s]+)>?")


def _p_mail(line: str, now: float) -> AuthEvent | None:
    m = _POSTFIX_SASL.search(line)
    if m:
        return AuthEvent("smtp", m.group("ip"), None, "fail", now, line.strip())
    if ("imap-login" in line or "pop3-login" in line or "dovecot" in line) and (
        "auth failed" in line or "authentication failure" in line
    ):
        rm = _RIP.search(line)
        if rm:
            um = _DOVE_USER.search(line)
            return AuthEvent("imap", rm.group("ip"), um.group("user") if um else None, "fail", now, line.strip())
    return None


# --- web app login (nginx/apache access log) ---
_WEB = re.compile(rf'^\s*{_IP}\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{{3}})')
_LOGIN_PATH = re.compile(r"(?:/login|/signin|/session|/wp-login\.php|/admin|/api/\w*(?:auth|login|token)\w*)", re.I)


def _p_web(line: str, now: float) -> AuthEvent | None:
    m = _WEB.search(line)
    if not m or not _LOGIN_PATH.search(m.group("path")):
        return None
    status = int(m.group("status"))
    if status in (200, 302):
        outcome = "success"
    elif status in (400, 401, 403, 422, 429):
        outcome = "fail"
    else:
        return None
    return AuthEvent("web", m.group("ip"), None, outcome, now, line.strip())


# --- Windows logon events (4625 fail / 4624 success), from forwarded/exported text ---
_WIN_FAIL = re.compile(r"(?:EventID[=:\s]*4625|An account failed to log on)")
_WIN_OK = re.compile(r"(?:EventID[=:\s]*4624|An account was successfully logged on)")
_WIN_IP = re.compile(rf"Source Network Address:\s*{_IP}")
_WIN_USER = re.compile(r"Account Name:\s*(?P<user>\S+)")


def _p_windows(line: str, now: float) -> AuthEvent | None:
    is_fail = _WIN_FAIL.search(line)
    is_ok = _WIN_OK.search(line)
    if not (is_fail or is_ok):
        return None
    im = _WIN_IP.search(line)
    um = _WIN_USER.search(line)
    return AuthEvent(
        "winrdp",
        im.group("ip") if im else None,
        um.group("user") if um else None,
        "success" if is_ok else "fail",
        now,
        line.strip(),
    )


PARSERS = [_p_ssh, _p_sudo_su, _p_pam, _p_ftp, _p_mail, _p_web, _p_windows]


def parse_auth_line(line: str, *, now: float) -> AuthEvent | None:
    """Turn one raw log line (any supported service) into an AuthEvent, or None."""
    for parser in PARSERS:
        ev = parser(line, now)
        if ev is not None:
            return ev
    return None


def parse_web_request(line: str, *, now: float) -> tuple[str, str, int] | None:
    """Return (ip, path, status) for any web access-log line, else None."""
    m = _WEB.search(line)
    if not m:
        return None
    return m.group("ip"), m.group("path"), int(m.group("status"))
