# ATT&CK coverage matrix

* Catalogue: Enterprise ATT&CK v20.0 (all non-revoked Enterprise techniques); 126 rules (version 2026.11.1) and 17 correlations; commit `1384acd`.
* **83 of 228 parent techniques** (36%) and 156 of 715 techniques including sub-techniques have at least one rule or correlation. Having a rule is not the same as detecting an attack that uses the technique; see the other columns.

Columns: *rule* = a rule or correlation names the technique (or one of its sub-techniques); *tested* = at least one labelled scenario exists; *detected* = at least one of those scenarios produced a hit. Held-out counts are numbers only: which techniques failed is not published here, to keep that set usable for the next round.

| Tactic | Techniques | With rule | Parents with rule | Tested (dev/tuning) | Detected (dev/tuning) | Tested (held-out) | Detected (held-out) |
|---|---|---|---|---|---|---|---|
| TA0043 Reconnaissance | 46 | 4 | 2/12 | 0 | 0 | 0 | 0 |
| TA0042 Resource Development | 51 | 0 | 0/9 | 0 | 0 | 0 | 0 |
| TA0001 Initial Access | 22 | 7 | 4/11 | 6 | 6 | 4 | 3 |
| TA0002 Execution | 63 | 17 | 9/21 | 19 | 15 | 18 | 15 |
| TA0003 Persistence | 113 | 27 | 10/21 | 31 | 26 | 30 | 21 |
| TA0004 Privilege Escalation | 96 | 29 | 10/13 | 29 | 26 | 30 | 23 |
| TA0005 Defense Evasion | 224 | 41 | 18/53 | 57 | 46 | 59 | 43 |
| TA0006 Credential Access | 68 | 20 | 8/18 | 27 | 21 | 25 | 18 |
| TA0007 Discovery | 49 | 9 | 7/34 | 26 | 16 | 25 | 12 |
| TA0008 Lateral Movement | 23 | 8 | 3/9 | 8 | 6 | 9 | 8 |
| TA0009 Collection | 41 | 9 | 7/17 | 12 | 7 | 8 | 4 |
| TA0011 Command and Control | 45 | 13 | 10/18 | 11 | 10 | 4 | 3 |
| TA0010 Exfiltration | 20 | 6 | 4/10 | 7 | 6 | 6 | 5 |
| TA0040 Impact | 33 | 10 | 10/15 | 10 | 10 | 6 | 5 |

## Parent techniques without any rule, by tactic

* **Reconnaissance** (10): T1590 Gather Victim Network Information, T1591 Gather Victim Org Information, T1592 Gather Victim Host Information, T1593 Search Open Websites/Domains, T1594 Search Victim-Owned Websites, T1596 Search Open Technical Databases, T1597 Search Closed Sources, T1598 Phishing for Information, T1681 Search Threat Vendor Data, T1682 Query Public AI Services
* **Resource Development** (9): T1583 Acquire Infrastructure, T1584 Compromise Infrastructure, T1585 Establish Accounts, T1586 Compromise Accounts, T1587 Develop Capabilities, T1588 Obtain Capabilities, T1608 Stage Capabilities, T1650 Acquire Access, T1683 Generate Content
* **Initial Access** (7): T1091 Replication Through Removable Media, T1189 Drive-by Compromise, T1195 Supply Chain Compromise, T1199 Trusted Relationship, T1200 Hardware Additions, T1659 Content Injection, T1669 Wi-Fi Networks
* **Execution** (12): T1072 Software Deployment Tools, T1106 Native API, T1129 Shared Modules, T1203 Exploitation for Client Execution, T1559 Inter-Process Communication, T1648 Serverless Execution, T1651 Cloud Administration Command, T1674 Input Injection, T1675 ESXi Administration Command, T1677 Poisoned Pipeline Execution, T1698 Indirect Prompt Injection, T1699 Direct Prompt Injection
* **Persistence** (11): T1037 Boot or Logon Initialization Scripts, T1137 Office Application Startup, T1176 Software Extensions, T1197 BITS Jobs, T1205 Traffic Signaling, T1525 Implant Internal Image, T1542 Pre-OS Boot, T1554 Compromise Host Software Binary, T1653 Power Settings, T1668 Exclusive Control, T1671 Cloud Application Integration
* **Privilege Escalation** (3): T1037 Boot or Logon Initialization Scripts, T1134 Access Token Manipulation, T1484 Domain or Tenant Policy Modification
* **Defense Evasion** (35): T1006 Direct Volume Access, T1134 Access Token Manipulation, T1197 BITS Jobs, T1205 Traffic Signaling, T1207 Rogue Domain Controller, T1211 Exploitation for Stealth, T1216 System Script Proxy Execution, T1220 XSL Script Processing, T1221 Template Injection, T1222 File and Directory Permissions Modification, T1480 Execution Guardrails, T1484 Domain or Tenant Policy Modification, T1497 Virtualization/Sandbox Evasion, T1535 Unused/Unsupported Cloud Regions, T1542 Pre-OS Boot, T1553 Subvert Trust Controls, T1564 Hide Artifacts, T1578 Modify Cloud Compute Infrastructure, T1599 Network Boundary Bridging, T1600 Weaken Encryption, T1601 Modify System Image, T1612 Build Image on Host, T1622 Debugger Evasion, T1647 Plist File Modification, T1666 Modify Cloud Resource Hierarchy, T1678 Delay Execution, T1679 Selective Exclusion, T1684 Social Engineering, T1685 Disable or Modify Tools, T1686 Disable or Modify System Firewall, T1687 Exploitation for Defense Impairment, T1688 Safe Mode Boot, T1689 Downgrade Attack, T1690 Prevent Command History Logging, T1696 Anti-Automation Evasion
* **Credential Access** (10): T1040 Network Sniffing, T1056 Input Capture, T1111 Multi-Factor Authentication Interception, T1187 Forced Authentication, T1212 Exploitation for Credential Access, T1528 Steal Application Access Token, T1539 Steal Web Session Cookie, T1606 Forge Web Credentials, T1649 Steal or Forge Authentication Certificates, T1697 Steal Application Specific Passwords
* **Discovery** (27): T1007 System Service Discovery, T1010 Application Window Discovery, T1012 Query Registry, T1016 System Network Configuration Discovery, T1018 Remote System Discovery, T1033 System Owner/User Discovery, T1040 Network Sniffing, T1049 System Network Connections Discovery, T1057 Process Discovery, T1082 System Information Discovery, T1083 File and Directory Discovery, T1120 Peripheral Device Discovery, T1124 System Time Discovery, T1201 Password Policy Discovery, T1217 Browser Information Discovery, T1497 Virtualization/Sandbox Evasion, T1518 Software Discovery, T1538 Cloud Service Dashboard, T1580 Cloud Infrastructure Discovery, T1614 System Location Discovery, T1615 Group Policy Discovery, T1619 Cloud Storage Object Discovery, T1622 Debugger Evasion, T1652 Device Driver Discovery, T1654 Log Enumeration, T1673 Virtual Machine Discovery, T1680 Local Storage Discovery
* **Lateral Movement** (6): T1072 Software Deployment Tools, T1080 Taint Shared Content, T1091 Replication Through Removable Media, T1210 Exploitation of Remote Services, T1534 Internal Spearphishing, T1563 Remote Service Session Hijacking
* **Collection** (10): T1025 Data from Removable Media, T1039 Data from Network Shared Drive, T1056 Input Capture, T1113 Screen Capture, T1115 Clipboard Data, T1119 Automated Collection, T1123 Audio Capture, T1125 Video Capture, T1185 Browser Session Hijacking, T1602 Data from Configuration Repository
* **Command and Control** (8): T1001 Data Obfuscation, T1008 Fallback Channels, T1092 Communication Through Removable Media, T1104 Multi-Stage Channels, T1132 Data Encoding, T1205 Traffic Signaling, T1659 Content Injection, T1665 Hide Infrastructure
* **Exfiltration** (6): T1011 Exfiltration Over Other Network Medium, T1020 Automated Exfiltration, T1029 Scheduled Transfer, T1030 Data Transfer Size Limits, T1041 Exfiltration Over C2 Channel, T1700 AI-Enabled Exfiltration
* **Impact** (5): T1491 Defacement, T1495 Firmware Corruption, T1565 Data Manipulation, T1657 Financial Theft, T1667 Email Bombing

## Reading this honestly

* A command-line and log-event detection engine cannot see most Resource Development, Reconnaissance (pre-compromise) or purely network/physical techniques; those gaps are structural, not backlog.
* Techniques with a rule may still be detected only in the forms the rule authors thought of; the evaluation report measures that on independent corpora.
* Behavioural detections (UEBA) map to a few techniques (T1078, T1021, T1098, T1530, T1213, T1041, T1048, T1071) and are listed under those, but they detect deviations, not the technique itself.
