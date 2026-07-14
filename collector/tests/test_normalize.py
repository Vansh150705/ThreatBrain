from tb_collector.normalize import normalize
from tb_collector.signatures import scan_line


def kinds(line):
    return {k for _, k, _, _ in scan_line(line)}


def test_url_encoded_sqli_decoded():
    assert "web_sqli" in kinds("/?id=1%27%20OR%201=1")


def test_double_encoded_sqli():
    assert "web_sqli" in kinds("/?id=1%2527%2520OR%25201=1")


def test_sql_comment_obfuscation():
    assert "web_sqli" in kinds("/?id=1 UNION/**/SELECT password")


def test_case_and_plus_whitespace():
    assert "web_sqli" in kinds("/?id=1+UnIoN+SeLeCt+x")


def test_encoded_path_traversal():
    assert "web_traversal" in kinds("/?file=..%2f..%2fetc%2fpasswd")


def test_normalize_plain_text_unchanged():
    assert normalize("hello world") == "hello world"


def test_benign_still_clean_after_normalize():
    assert kinds('1.2.3.4 - - [t] "GET /?id=5&name=john HTTP/1.1" 200 1 "-" "Mozilla/5.0"') == set()
