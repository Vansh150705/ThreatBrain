from tb_collector.parsing import parse_auth_line


# --- SSH ---
def test_parse_ssh_fail():
    ev = parse_auth_line(
        "May 26 14:01 kali sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", now=1.0
    )
    assert ev.service == "ssh" and ev.source_ip == "1.2.3.4"
    assert ev.username == "root" and ev.outcome == "fail"


def test_parse_ssh_invalid_user():
    ev = parse_auth_line(
        "sshd[1]: Failed password for invalid user admin from 5.6.7.8 port 1 ssh2", now=1.0
    )
    assert ev.outcome == "invalid" and ev.username == "admin"


def test_parse_ssh_success():
    ev = parse_auth_line("sshd[1]: Accepted password for jane from 9.9.9.9 port 2 ssh2", now=1.0)
    assert ev.outcome == "success" and ev.username == "jane" and ev.source_ip == "9.9.9.9"


# --- sudo/su ---
def test_parse_sudo_fail():
    ev = parse_auth_line(
        "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 user=bob", now=1.0
    )
    assert ev.service == "sudo" and ev.outcome == "fail" and ev.username == "bob"


# --- generic PAM (e.g. vsftpd via PAM) — not double-counted for sshd ---
def test_parse_pam_ftp_via_rhost():
    ev = parse_auth_line(
        "vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=203.0.113.5 user=bob", now=1.0
    )
    assert ev.service == "ftp" and ev.source_ip == "203.0.113.5" and ev.username == "bob"


def test_pam_sshd_line_not_double_counted():
    # sshd also emits a pam_unix(sshd:auth) line per failure; the PAM parser must ignore it
    ev = parse_auth_line("sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4", now=1.0)
    assert ev is None


# --- FTP own log ---
def test_parse_vsftpd_fail():
    ev = parse_auth_line('Mon Jul 13 vsftpd: FAIL LOGIN: Client "198.51.100.7"', now=1.0)
    assert ev.service == "ftp" and ev.source_ip == "198.51.100.7" and ev.outcome == "fail"


# --- mail ---
def test_parse_postfix_sasl_fail():
    ev = parse_auth_line(
        "postfix/smtpd[1]: warning: unknown[203.0.113.9]: SASL LOGIN authentication failed", now=1.0
    )
    assert ev.service == "smtp" and ev.source_ip == "203.0.113.9" and ev.outcome == "fail"


def test_parse_dovecot_fail():
    ev = parse_auth_line(
        "dovecot: imap-login: Disconnected (auth failed, 1 attempts): user=<bob>, method=PLAIN, rip=198.51.100.4, lip=10.0.0.1",
        now=1.0,
    )
    assert ev.service == "imap" and ev.source_ip == "198.51.100.4" and ev.username == "bob"


# --- web app login ---
def test_parse_web_login_fail():
    ev = parse_auth_line(
        '203.0.113.5 - - [13/Jul/2026:09:00:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8"', now=1.0
    )
    assert ev.service == "web" and ev.source_ip == "203.0.113.5" and ev.outcome == "fail"


def test_parse_web_login_success():
    ev = parse_auth_line(
        '203.0.113.5 - - [13/Jul/2026:09:00:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8"', now=1.0
    )
    assert ev.outcome == "success"


def test_parse_web_non_login_ignored():
    ev = parse_auth_line(
        '203.0.113.5 - - [13/Jul/2026:09:00:00 +0000] "GET /index.html HTTP/1.1" 200 100 "-" "curl/8"', now=1.0
    )
    assert ev is None


# --- Windows ---
def test_parse_windows_4625_fail():
    line = "EventID=4625 An account failed to log on Account Name: bob Source Network Address: 203.0.113.8"
    ev = parse_auth_line(line, now=1.0)
    assert ev.service == "winrdp" and ev.source_ip == "203.0.113.8" and ev.outcome == "fail"


def test_parse_windows_4624_success():
    line = "EventID=4624 An account was successfully logged on Account Name: bob Source Network Address: 203.0.113.8"
    ev = parse_auth_line(line, now=1.0)
    assert ev.outcome == "success"


def test_parse_non_auth_returns_none():
    assert parse_auth_line("just a normal syslog line", now=1.0) is None
