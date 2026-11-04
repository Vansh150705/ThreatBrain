# ThreatBrain validation report

* Result: **PASS**  · mode `engine` · commit `6c4c646` · rules `2026.11.1` (104 rules) · 2026-11-04T05:11:19Z
* Fidelity: detection engine + correlation only; no database, no LLM

## Headline metrics

| Metric | Value |
|---|---|
| attack_scenarios | 169 |
| true_positives | 169 |
| false_negatives | 0 |
| benign_scenarios | 125 |
| false_positives | 0 |
| recall | 1.0 |
| precision | 1.0 |
| f1 | 1.0 |
| false_positive_rate | 0.0 |
| mapping_accuracy | 0.9941 |
| chain_recall | 1.0 |
| chain_negative_pass | 1.0 |

## Gates

| Gate | Result |
|---|---|
| attack_recall_min | pass |
| precision_min | pass |
| benign_fpr_max | pass |
| mapping_accuracy_min | pass |
| chain_recall_min | pass |
| chain_negative_pass_min | pass |
| no_unexpected_evasion_misses | pass |
| engine_event_p95_ms_max | pass |

## Recall by tactic

| Tactic | Scenarios | Detected | Recall |
|---|---|---|---|
| TA0001 | 24 | 24 | 1.0 |
| TA0002 | 14 | 14 | 1.0 |
| TA0003 | 19 | 19 | 1.0 |
| TA0004 | 10 | 10 | 1.0 |
| TA0005 | 23 | 23 | 1.0 |
| TA0006 | 21 | 21 | 1.0 |
| TA0007 | 7 | 7 | 1.0 |
| TA0008 | 7 | 7 | 1.0 |
| TA0009 | 8 | 8 | 1.0 |
| TA0010 | 6 | 6 | 1.0 |
| TA0011 | 15 | 15 | 1.0 |
| TA0040 | 15 | 15 | 1.0 |

## Missed attack scenarios

* none

## Accepted detection gaps (excluded from recall; reason documented)

* `HL2-011` CloudTrail secret read by unfamiliar principal from outside: needs a per-principal behavioural baseline; a successful GetSecretValue is normal for most workloads. The adapter now keeps the event, but no rule fires on it.

## False positives on benign hard negatives

* none

## Detected but mapped to a different technique family

* `HL2-014` Offensive tool crackmapexec expected ['T1021'] got rules ['TB-CRED-004']

## Evasion probes

11/12 detected. Open documented gaps: 1.
* `EVA-001` PowerShell with string concatenation to hide IEX: detected (known gap)
* `EVA-002` Reverse shell via renamed netcat: detected (known gap)
* `EVA-003` Defender disabled via registry through reg import: detected (known gap)
* `EVA-004` Log clearing with PowerShell .NET API: detected (known gap)
* `EVA-005` Credential dump via direct syscalls tool with innocuous name: detected (known gap)
* `EVA-006` Exfil over HTTPS to attacker domain with no tooling signature: MISSED (known gap)
* `EVA-007` base64 split across arguments: detected
* `EVA-008` Case and whitespace variation of a known command: detected
* `EVA-009` Quoted path variation of wevtutil: detected
* `EVA-010` URL-encoded path traversal: detected
* `EVA-011` Double URL-encoded traversal: detected (known gap)
* `EVA-012` Mixed-case JNDI with nested lookups: detected

**Gaps closed (remove `known_gap`)**: ['EVA-001', 'EVA-002', 'EVA-003', 'EVA-004', 'EVA-005', 'EVA-011']

## Campaign correlation

* `CHN-001` Spray, then successful login from same IP: pass (fired ['TB-COR-001'])
* `CHN-002` Scan, then SQL injection from same source: pass (fired ['TB-COR-002'])
* `CHN-003` Exploit, then reverse shell on same host: pass (fired ['TB-COR-003'])
* `CHN-004` Credential dump, then PsExec by the same account: pass (fired ['TB-COR-004'])
* `CHN-005` Staging archive, then upload with rclone: pass (fired ['TB-COR-005'])
* `CHN-006` Defender disabled, then shadow copies deleted: pass (fired ['TB-COR-006', 'TB-COR-012'])
* `CHN-007` Phishing attachment, then macro-spawned PowerShell for the same user: pass (fired ['TB-COR-008'])
* `CHN-008` Privilege grant, then CloudTrail disabled by the same principal: pass (fired ['TB-COR-009'])
* `CHN-009` Web shell then persistence: pass (fired ['TB-COR-003', 'TB-COR-010'])
* `CHN-010` Container shell then privileged container: pass (fired ['TB-COR-011'])
* `CHN-011` Ransomware precursors: pass (fired ['TB-COR-012'])
* `CHN-012` Three tactics on one host: pass (fired ['TB-COR-007'])
* `CHN-013` Twelve failed logins in under ten minutes from one source: pass (fired ['TB-COR-013'])
* `CHN-014` Failed logins against seven different accounts from one source: pass (fired ['TB-COR-014'])
* `CHN-N01` Success before the spray: pass (fired [])
* `CHN-N02` Spray and success from different IPs: pass (fired [])
* `CHN-N03` Spray and success three hours apart (window is two hours): pass (fired [])
* `CHN-N04` Exploit and shell on different hosts: pass (fired [])
* `CHN-N05` Same precursor repeated is not a pair: pass (fired [])
* `CHN-N06` Eight failed logins is below the burst threshold: pass (fired [])
* `CHN-N07` Many failures but spread over two hours: pass (fired [])

## Latency

`{"events": 381, "p50": 0.569, "p95": 1.306, "p99": 2.282, "max": 4.173, "mean": 0.708}`

## ATT&CK coverage (catalog subset)

| Tactic | Catalog | With rule | Tested | Detected |
|---|---|---|---|---|
| Reconnaissance | 4 | 3 | 0 | 0 |
| Resource Development | 0 | 0 | 0 | 0 |
| Initial Access | 9 | 6 | 5 | 5 |
| Execution | 16 | 11 | 8 | 8 |
| Persistence | 23 | 18 | 17 | 17 |
| Privilege Escalation | 23 | 20 | 18 | 18 |
| Defense Evasion | 39 | 28 | 21 | 21 |
| Credential Access | 22 | 17 | 15 | 14 |
| Discovery | 18 | 7 | 6 | 6 |
| Lateral Movement | 8 | 6 | 3 | 3 |
| Collection | 12 | 7 | 6 | 6 |
| Command and Control | 12 | 12 | 8 | 8 |
| Exfiltration | 8 | 5 | 4 | 4 |
| Impact | 11 | 10 | 7 | 7 |

## Limitations of this benchmark

* Scenarios were authored by the same team that wrote the rules; they are modelled on public emulation procedures but are NOT an independent benchmark. Scores will overstate real-world detection.
* All telemetry is synthetic event data. No real malware, credentials, or exploitation were used, and no attack command was executed.
* Benign hard negatives are a small hand-picked set (a few dozen kinds of legitimate activity, each appearing once). Production false-positive rates depend on your environment and must be measured on your own telemetry.
* LLM quality is not measured: the pipeline runs with a scripted model and an in-memory database stand-in. No live Groq/Supabase behaviour is verified by this report.
* Detection is per-event and sequence/threshold correlation within a window; it does not model statistical baselines or UEBA.
