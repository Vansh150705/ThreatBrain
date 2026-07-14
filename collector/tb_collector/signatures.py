from __future__ import annotations

import re

from tb_collector.normalize import normalize

# Signature-based detection for attacks whose payload appears in a single request
# line (web exploits, scanner tools). Each line is checked in BOTH its raw form
# and a decoded/deobfuscated form (see normalize), so URL-encoding, double-
# encoding, SQL comments and whitespace tricks don't hide the payload.
#
# (display_name, kind, severity, mitre_tuple, compiled_regex)
_SIGNATURES = [
    ("SQL injection", "web_sqli", "high", ("T1190",), re.compile(
        r"(?:union\s+(?:all\s+)?select|\b(?:or|and)\s+1\s*=\s*1\b|'\s*or\s*'"
        r"|'\s*or\s*'1'\s*=\s*'1|'\s*(?:--|#)|information_schema|sleep\s*\(\s*\d"
        r"|benchmark\s*\(|xp_cmdshell|waitfor\s+delay|\bdrop\s+table\b|\binsert\s+into\b)",
        re.I)),
    ("Cross-site scripting", "web_xss", "high", ("T1190", "T1059.007"), re.compile(
        r"(?:<script\b|%3cscript|onerror\s*=|onload\s*=|onmouseover\s*=|javascript:"
        r"|<svg\b|<iframe\b|<img[^>]+src|document\.cookie|data:text/html)", re.I)),
    ("Path traversal / LFI", "web_traversal", "high", ("T1083", "T1190"), re.compile(
        r"(?:\.\.[\\/]\.\.|\.\.%2f|%2e%2e%2f|/etc/passwd|/proc/self/|boot\.ini"
        r"|php://(?:filter|input)|file:///|/windows/win\.ini)", re.I)),
    ("Command injection", "web_cmdi", "high", ("T1059",), re.compile(
        r"(?:(?:[;|]|\|\||&&)\s*(?:cat|ls|wget|curl|nc|bash|sh|ping|uname)\s+[\w/.\-]"
        r"|(?:[;|]|&&)\s*(?:whoami|id)\b(?!\s*=)|/bin/(?:bash|sh)|\$\{ifs\}|\$ifs"
        r"|%0a\s*(?:cat|id|whoami|ls)|\$\([^)]+\)|`[^`]+`)", re.I)),
    ("Log4Shell (JNDI)", "web_log4shell", "critical", ("T1190",), re.compile(
        r"(?:\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop)|\$\{[^}]{0,60}(?:ldap|rmi|dns|iiop)s?://)",
        re.I)),
    ("Scanner / recon tool", "scanner_tool", "medium", ("T1595",), re.compile(
        r"\b(?:sqlmap|nikto|nmap|masscan|gobuster|dirbuster|feroxbuster|nuclei|wpscan"
        r"|acunetix|nessus|zgrab|wfuzz|ffuf)\b", re.I)),
]


def scan_line(line: str) -> list[tuple[str, str, str, tuple]]:
    """Return (name, kind, severity, mitre) for each signature matching the line.

    The line is checked raw and normalized (decoded/deobfuscated); results are
    de-duplicated by kind so an obfuscated payload isn't reported twice.
    """
    hits: dict[str, tuple[str, str, str, tuple]] = {}
    for text in (line, normalize(line)):
        for name, kind, sev, mitre, rx in _SIGNATURES:
            if kind not in hits and rx.search(text):
                hits[kind] = (name, kind, sev, mitre)
    return list(hits.values())
