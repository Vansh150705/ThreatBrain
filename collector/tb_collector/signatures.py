from __future__ import annotations

import re

# Signature-based detection for attacks that show up as a payload in a single
# request line (web exploits, scanner tools) — as opposed to the rate/behaviour
# based brute-force detectors. Each match fires one Detection (the engine adds a
# per-IP-per-kind cooldown so one scan campaign is a few events, not thousands).
#
# (display_name, kind, severity, mitre_tuple, compiled_regex)
_SIGNATURES = [
    ("SQL injection", "web_sqli", "high", ("T1190",), re.compile(
        r"(?:union\s+(?:all\s+)?select|\bor\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1"
        r"|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|xp_cmdshell|waitfor\s+delay)",
        re.I)),
    ("Cross-site scripting", "web_xss", "high", ("T1190", "T1059.007"), re.compile(
        r"(?:<script\b|%3cscript|onerror\s*=|onload\s*=|javascript:|<svg[^>]+on\w+=)", re.I)),
    ("Path traversal / LFI", "web_traversal", "high", ("T1083", "T1190"), re.compile(
        r"(?:\.\./\.\.|\.\.%2f|%2e%2e%2f|/etc/passwd|/proc/self/environ"
        r"|php://(?:filter|input)|file:///|/windows/win\.ini)", re.I)),
    ("Command injection", "web_cmdi", "high", ("T1059",), re.compile(
        r"(?:(?:[;|]|\|\||&&)\s*(?:cat|ls|wget|curl|nc|bash|sh|ping|uname)\s+[\w/.\-]"
        r"|(?:[;|]|&&)\s*(?:whoami|id)\b(?!\s*=)|\$\([^)]+\)|`[^`]+`)", re.I)),
    ("Log4Shell (JNDI)", "web_log4shell", "critical", ("T1190",), re.compile(
        r"\$\{jndi:(?:ldap|ldaps|rmi|dns|iiop)", re.I)),
    ("Scanner / recon tool", "scanner_tool", "medium", ("T1595",), re.compile(
        r"\b(?:sqlmap|nikto|nmap|masscan|gobuster|dirbuster|feroxbuster|nuclei|wpscan"
        r"|acunetix|nessus|zgrab|wfuzz|ffuf)\b", re.I)),
]


def scan_line(line: str) -> list[tuple[str, str, str, tuple]]:
    """Return (name, kind, severity, mitre) for each signature that matches the line."""
    hits: list[tuple[str, str, str, tuple]] = []
    for name, kind, sev, mitre, rx in _SIGNATURES:
        if rx.search(line):
            hits.append((name, kind, sev, mitre))
    return hits
