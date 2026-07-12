from tb_collector.adapters.ssh_bruteforce import AuthLogSSHBruteForce

FAIL = "May 26 14:01:02 kali sshd[1234]: Failed password for root from 203.0.113.42 port 55214 ssh2"
FAIL_INVALID = "May 26 14:01:03 kali sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 55215 ssh2"
OTHER = "May 26 14:01:04 kali sshd[1234]: Accepted password for jane from 10.0.0.5 port 500 ssh2"


def test_below_threshold_no_detection():
    a = AuthLogSSHBruteForce(threshold=5, window_seconds=60)
    for i in range(4):
        assert a.process_line(FAIL, now=float(i)) is None


def test_threshold_trips_once_and_reports_ip_and_user():
    a = AuthLogSSHBruteForce(threshold=5, window_seconds=60)
    out = None
    for i in range(5):
        out = a.process_line(FAIL, now=float(i))
    assert out is not None
    assert out.source_ip == "203.0.113.42"
    assert out.username == "root"
    assert out.count == 5


def test_invalid_user_line_is_parsed():
    a = AuthLogSSHBruteForce(threshold=1, window_seconds=60)
    out = a.process_line(FAIL_INVALID, now=0.0)
    assert out is not None
    assert out.username == "admin"


def test_non_failure_lines_ignored():
    a = AuthLogSSHBruteForce(threshold=1, window_seconds=60)
    assert a.process_line(OTHER, now=0.0) is None
    assert a.process_line("garbage", now=1.0) is None


def test_cooldown_suppresses_repeat_detections():
    a = AuthLogSSHBruteForce(threshold=3, window_seconds=60, cooldown_seconds=300)
    first = None
    for i in range(3):
        first = a.process_line(FAIL, now=float(i))
    assert first is not None
    # more failures during cooldown -> no new detection
    assert a.process_line(FAIL, now=10.0) is None
    assert a.process_line(FAIL, now=20.0) is None
    # after cooldown, a fresh burst detects again
    out = None
    for j in range(3):
        out = a.process_line(FAIL, now=400.0 + j)
    assert out is not None


def test_window_evicts_old_attempts():
    a = AuthLogSSHBruteForce(threshold=3, window_seconds=60)
    assert a.process_line(FAIL, now=0.0) is None
    assert a.process_line(FAIL, now=1.0) is None
    # third attempt is outside the 60s window from the first two -> only 1 in window
    assert a.process_line(FAIL, now=120.0) is None
