from tb_collector.parsing import parse_auth_line


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


def test_parse_sudo_fail():
    ev = parse_auth_line(
        "sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 user=bob", now=1.0
    )
    assert ev.service == "sudo" and ev.outcome == "fail" and ev.username == "bob"


def test_parse_non_auth_returns_none():
    assert parse_auth_line("just a normal syslog line", now=1.0) is None
