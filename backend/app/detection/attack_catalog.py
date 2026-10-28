"""Curated MITRE ATT&CK (Enterprise) catalogue: technique id -> (name, tactic ids).

A *subset* sufficient for the platform's rules, correlations and the validation
coverage matrix, not the full framework. It exists so that
  * rule/agent output can be validated against real technique ids (no invented IDs),
  * tactics can be derived from techniques consistently,
  * the validation lab can report coverage per tactic.
Extend it as rules are added; ``tests/test_attack_catalog.py`` keeps every
built-in rule and correlation consistent with it.
"""

from __future__ import annotations

TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}

_T = {
    # Reconnaissance
    "T1595": ("Active Scanning", ["TA0043"]),
    "T1595.002": ("Vulnerability Scanning", ["TA0043"]),
    "T1589.001": ("Gather Victim Identity Information: Credentials", ["TA0043"]),
    "T1592": ("Gather Victim Host Information", ["TA0043"]),
    # Initial access
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1133": ("External Remote Services", ["TA0001", "TA0003"]),
    "T1566": ("Phishing", ["TA0001"]),
    "T1566.001": ("Spearphishing Attachment", ["TA0001"]),
    "T1566.002": ("Spearphishing Link", ["TA0001"]),
    "T1078": ("Valid Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1078.004": ("Valid Accounts: Cloud Accounts", ["TA0001", "TA0003", "TA0004", "TA0005"]),
    "T1195": ("Supply Chain Compromise", ["TA0001"]),
    "T1199": ("Trusted Relationship", ["TA0001"]),
    # Execution
    "T1059": ("Command and Scripting Interpreter", ["TA0002"]),
    "T1059.001": ("PowerShell", ["TA0002"]),
    "T1059.003": ("Windows Command Shell", ["TA0002"]),
    "T1059.004": ("Unix Shell", ["TA0002"]),
    "T1059.005": ("Visual Basic", ["TA0002"]),
    "T1059.006": ("Python", ["TA0002"]),
    "T1059.007": ("JavaScript", ["TA0002"]),
    "T1047": ("Windows Management Instrumentation", ["TA0002"]),
    "T1053": ("Scheduled Task/Job", ["TA0002", "TA0003", "TA0004"]),
    "T1053.003": ("Cron", ["TA0002", "TA0003", "TA0004"]),
    "T1053.005": ("Scheduled Task", ["TA0002", "TA0003", "TA0004"]),
    "T1204": ("User Execution", ["TA0002"]),
    "T1204.002": ("Malicious File", ["TA0002"]),
    "T1569.002": ("Service Execution", ["TA0002"]),
    "T1609": ("Container Administration Command", ["TA0002"]),
    "T1610": ("Deploy Container", ["TA0002", "TA0005"]),
    # Persistence
    "T1136": ("Create Account", ["TA0003"]),
    "T1136.001": ("Local Account", ["TA0003"]),
    "T1136.003": ("Cloud Account", ["TA0003"]),
    "T1098": ("Account Manipulation", ["TA0003", "TA0004"]),
    "T1098.001": ("Additional Cloud Credentials", ["TA0003", "TA0004"]),
    "T1098.003": ("Additional Cloud Roles", ["TA0003", "TA0004"]),
    "T1098.004": ("SSH Authorized Keys", ["TA0003"]),
    "T1543.002": ("Systemd Service", ["TA0003", "TA0004"]),
    "T1543.003": ("Windows Service", ["TA0003", "TA0004"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["TA0003", "TA0004"]),
    "T1505.003": ("Web Shell", ["TA0003"]),
    "T1546.004": ("Unix Shell Configuration Modification", ["TA0003", "TA0004"]),
    "T1546.003": ("Windows Management Instrumentation Event Subscription", ["TA0003", "TA0004"]),
    "T1574.006": ("Dynamic Linker Hijacking", ["TA0003", "TA0004", "TA0005"]),
    "T1037": ("Boot or Logon Initialization Scripts", ["TA0003", "TA0004"]),
    # Privilege escalation
    "T1068": ("Exploitation for Privilege Escalation", ["TA0004"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["TA0004", "TA0005"]),
    "T1548.001": ("Setuid and Setgid", ["TA0004", "TA0005"]),
    "T1548.002": ("Bypass User Account Control", ["TA0004", "TA0005"]),
    "T1548.003": ("Sudo and Sudo Caching", ["TA0004", "TA0005"]),
    "T1134": ("Access Token Manipulation", ["TA0004", "TA0005"]),
    "T1611": ("Escape to Host", ["TA0004"]),
    "T1055": ("Process Injection", ["TA0004", "TA0005"]),
    # Defense evasion
    "T1027": ("Obfuscated Files or Information", ["TA0005"]),
    "T1070": ("Indicator Removal", ["TA0005"]),
    "T1070.001": ("Clear Windows Event Logs", ["TA0005"]),
    "T1070.002": ("Clear Linux or Mac System Logs", ["TA0005"]),
    "T1070.003": ("Clear Command History", ["TA0005"]),
    "T1070.004": ("File Deletion", ["TA0005"]),
    "T1112": ("Modify Registry", ["TA0005"]),
    "T1140": ("Deobfuscate/Decode Files or Information", ["TA0005"]),
    "T1218": ("System Binary Proxy Execution", ["TA0005"]),
    "T1218.005": ("Mshta", ["TA0005"]),
    "T1218.010": ("Regsvr32", ["TA0005"]),
    "T1218.011": ("Rundll32", ["TA0005"]),
    "T1197": ("BITS Jobs", ["TA0005", "TA0003"]),
    "T1202": ("Indirect Command Execution", ["TA0005"]),
    "T1036": ("Masquerading", ["TA0005"]),
    "T1562": ("Impair Defenses", ["TA0005"]),
    "T1562.001": ("Disable or Modify Tools", ["TA0005"]),
    "T1562.004": ("Disable or Modify System Firewall", ["TA0005"]),
    "T1562.006": ("Indicator Blocking", ["TA0005"]),
    "T1562.007": ("Disable or Modify Cloud Firewall", ["TA0005"]),
    "T1562.008": ("Disable or Modify Cloud Logs", ["TA0005"]),
    "T1578": ("Modify Cloud Compute Infrastructure", ["TA0005"]),
    "T1553": ("Subvert Trust Controls", ["TA0005"]),
    "T1620": ("Reflective Code Loading", ["TA0005"]),
    # Credential access
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.001": ("Password Guessing", ["TA0006"]),
    "T1110.003": ("Password Spraying", ["TA0006"]),
    "T1110.004": ("Credential Stuffing", ["TA0006"]),
    "T1003": ("OS Credential Dumping", ["TA0006"]),
    "T1003.001": ("LSASS Memory", ["TA0006"]),
    "T1003.002": ("Security Account Manager", ["TA0006"]),
    "T1003.003": ("NTDS", ["TA0006"]),
    "T1003.008": ("/etc/passwd and /etc/shadow", ["TA0006"]),
    "T1552": ("Unsecured Credentials", ["TA0006"]),
    "T1552.001": ("Credentials In Files", ["TA0006"]),
    "T1552.005": ("Cloud Instance Metadata API", ["TA0006"]),
    "T1555": ("Credentials from Password Stores", ["TA0006"]),
    "T1555.003": ("Credentials from Web Browsers", ["TA0006"]),
    "T1110.002": ("Password Cracking", ["TA0006"]),
    "T1558.003": ("Kerberoasting", ["TA0006"]),
    "T1556": ("Modify Authentication Process", ["TA0006", "TA0005", "TA0003"]),
    "T1621": ("Multi-Factor Authentication Request Generation", ["TA0006"]),
    "T1539": ("Steal Web Session Cookie", ["TA0006"]),
    "T1528": ("Steal Application Access Token", ["TA0006"]),
    # Discovery
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1087": ("Account Discovery", ["TA0007"]),
    "T1087.001": ("Local Account", ["TA0007"]),
    "T1087.002": ("Domain Account", ["TA0007"]),
    "T1482": ("Domain Trust Discovery", ["TA0007"]),
    "T1201": ("Password Policy Discovery", ["TA0007"]),
    "T1135": ("Network Share Discovery", ["TA0007"]),
    "T1082": ("System Information Discovery", ["TA0007"]),
    "T1083": ("File and Directory Discovery", ["TA0007"]),
    "T1018": ("Remote System Discovery", ["TA0007"]),
    "T1057": ("Process Discovery", ["TA0007"]),
    "T1069": ("Permission Groups Discovery", ["TA0007"]),
    "T1033": ("System Owner/User Discovery", ["TA0007"]),
    "T1016": ("System Network Configuration Discovery", ["TA0007"]),
    "T1613": ("Container and Resource Discovery", ["TA0007"]),
    "T1526": ("Cloud Service Discovery", ["TA0007"]),
    "T1580": ("Cloud Infrastructure Discovery", ["TA0007"]),
    "T1619": ("Cloud Storage Object Discovery", ["TA0007"]),
    # Lateral movement
    "T1021": ("Remote Services", ["TA0008"]),
    "T1021.001": ("Remote Desktop Protocol", ["TA0008"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["TA0008"]),
    "T1021.004": ("SSH", ["TA0008"]),
    "T1021.006": ("Windows Remote Management", ["TA0008"]),
    "T1570": ("Lateral Tool Transfer", ["TA0008"]),
    "T1550": ("Use Alternate Authentication Material", ["TA0005", "TA0008"]),
    "T1550.002": ("Pass the Hash", ["TA0005", "TA0008"]),
    # Collection
    "T1005": ("Data from Local System", ["TA0009"]),
    "T1039": ("Data from Network Shared Drive", ["TA0009"]),
    "T1119": ("Automated Collection", ["TA0009"]),
    "T1074": ("Data Staged", ["TA0009"]),
    "T1560": ("Archive Collected Data", ["TA0009"]),
    "T1560.001": ("Archive via Utility", ["TA0009"]),
    "T1530": ("Data from Cloud Storage", ["TA0009"]),
    "T1213": ("Data from Information Repositories", ["TA0009"]),
    "T1114": ("Email Collection", ["TA0009"]),
    "T1114.003": ("Email Forwarding Rule", ["TA0009"]),
    # Command and control
    "T1071": ("Application Layer Protocol", ["TA0011"]),
    "T1071.001": ("Web Protocols", ["TA0011"]),
    "T1071.004": ("DNS", ["TA0011"]),
    "T1095": ("Non-Application Layer Protocol", ["TA0011"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1571": ("Non-Standard Port", ["TA0011"]),
    "T1572": ("Protocol Tunneling", ["TA0011"]),
    "T1573": ("Encrypted Channel", ["TA0011"]),
    "T1090": ("Proxy", ["TA0011"]),
    "T1219": ("Remote Access Software", ["TA0011"]),
    "T1568": ("Dynamic Resolution", ["TA0011"]),
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", ["TA0010"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", ["TA0010"]),
    "T1567": ("Exfiltration Over Web Service", ["TA0010"]),
    "T1567.002": ("Exfiltration to Cloud Storage", ["TA0010"]),
    "T1537": ("Transfer Data to Cloud Account", ["TA0010"]),
    "T1020": ("Automated Exfiltration", ["TA0010"]),
    "T1052.001": ("Exfiltration over USB", ["TA0010"]),
    "T1102": ("Web Service", ["TA0011"]),
    # Impact
    "T1485": ("Data Destruction", ["TA0040"]),
    "T1486": ("Data Encrypted for Impact", ["TA0040"]),
    "T1490": ("Inhibit System Recovery", ["TA0040"]),
    "T1489": ("Service Stop", ["TA0040"]),
    "T1496": ("Resource Hijacking", ["TA0040"]),
    "T1498": ("Network Denial of Service", ["TA0040"]),
    "T1499": ("Endpoint Denial of Service", ["TA0040"]),
    "T1531": ("Account Access Removal", ["TA0040"]),
    "T1529": ("System Shutdown/Reboot", ["TA0040"]),
}

TECHNIQUES: dict[str, dict[str, object]] = {
    tid: {"name": name, "tactics": tactics} for tid, (name, tactics) in _T.items()
}


def technique_name(tid: str) -> str | None:
    t = TECHNIQUES.get(tid)
    return str(t["name"]) if t else None


def tactics_for(techniques: list[str]) -> list[str]:
    """Union of the tactics of the given techniques (catalogue order, de-duplicated)."""
    out: list[str] = []
    for tid in techniques:
        for tac in TECHNIQUES.get(tid, {}).get("tactics", []):  # type: ignore[union-attr]
            if tac not in out:
                out.append(tac)
    return out


def is_known(tid: str) -> bool:
    return tid in TECHNIQUES or tid in TACTICS


def validate_ids(techniques: list[str], tactics: list[str] | None = None) -> list[str]:
    """Human-readable problems with a rule's ATT&CK ids (empty list = consistent)."""
    problems: list[str] = []
    for t in techniques:
        if t not in TECHNIQUES:
            problems.append(f"unknown technique {t}")
    for tac in tactics or []:
        if tac not in TACTICS:
            problems.append(f"unknown tactic {tac}")
    known = tactics_for(techniques)
    for tac in tactics or []:
        if known and tac not in known:
            problems.append(f"tactic {tac} is not a tactic of {', '.join(techniques)}")
    return problems
