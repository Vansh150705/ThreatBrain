from tb_collector.detectors import WebScanning
from tb_collector.engine import DetectionEngine, default_detectors


def _engine(**kw):
    return DetectionEngine(default_detectors(**kw))


def test_rsyslog_repeat_expands_count():
    e = _engine(threshold=10, window=60)
    line = "sshd[1]: message repeated 12 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]"
    dets = e.process_line(line, now=1.0)
    bf = [d for d in dets if d.kind == "brute_force"]
    assert bf and bf[0].count >= 12


def test_success_after_failures_flags_compromise():
    e = _engine(threshold=1000)  # keep the per-source detector quiet
    for i in range(6):
        e.process_line(f"Failed password for root from 2.2.2.2 port {i} ssh2", now=float(i))
    dets = e.process_line("Accepted password for root from 2.2.2.2 port 9 ssh2", now=10.0)
    assert any(d.kind == "brute_force_success" and d.severity == "critical" for d in dets)


def test_non_auth_line_yields_nothing():
    assert _engine().process_line("nothing to see here", now=1.0) == []


def test_web_sqli_signature_detected():
    e = _engine()
    line = '203.0.113.5 - - [t] "GET /?id=1\' OR 1=1-- HTTP/1.1" 200 10 "-" "curl/8"'
    dets = e.process_line(line, now=1.0)
    assert any(d.kind == "web_sqli" and d.source_ip == "203.0.113.5" for d in dets)


def test_signature_cooldown_dedupes():
    e = _engine()
    line = '203.0.113.5 - - [t] "GET /?id=1\' OR 1=1-- HTTP/1.1" 200 10 "-" "curl/8"'
    assert e.process_line(line, now=1.0)  # fires
    assert e.process_line(line, now=2.0) == []  # same ip+kind within cooldown -> quiet


def test_obfuscated_sqli_detected_via_engine():
    e = _engine()
    line = '203.0.113.5 - - [t] "GET /?id=1%27%20OR%201=1 HTTP/1.1" 200 10 "-" "Mozilla/5.0"'
    dets = e.process_line(line, now=1.0)
    assert any(d.kind == "web_sqli" for d in dets)


def test_behavioural_web_scanning_via_engine():
    e = DetectionEngine(default_detectors(), web_scanner=WebScanning(distinct_paths=3, window=60))
    out = []
    for i in range(3):
        line = f'9.9.9.9 - - [t] "GET /page{i} HTTP/1.1" 404 1 "-" "Mozilla/5.0"'
        out += e.process_line(line, now=float(i))
    assert any(d.kind == "web_scanning" for d in out)
