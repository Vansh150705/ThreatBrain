# Validation history (append-only)

Every row is a real run of `python -m validation.runner --mode engine`. Numbers are never edited after the fact;
remediation is recorded as a new row. All scenarios are synthetic and authored by the rule authors (see
the limitations in each report), so these scores are optimistic compared with an independent benchmark.

## Round 0: initial corpus (attacks.yaml 90 / benign.yaml 70 / chains / evasion)

First run, before any remediation:

| Metric | Value |
|---|---|
| Attack recall | 88/90 = 0.978 |
| Benign false positives | 1/70 = 0.014 |
| Precision | 0.989 |
| Evasion probes detected | 4/12 (7 open documented gaps, 1 unexpected miss: EVA-009) |

Defects found by the run and fixed (each is a product bug, not a corpus edit):

1. `ATK-072` missed: event flattening stopped at depth 6, so the CIDR inside a CloudTrail `ipPermissions.items[].ipRanges.items[].cidrIp`
   was never visible to rules (a blind spot for every deeply nested audit log). Depth is now 16 with a node budget of 5000.
2. `ATK-057` missed: `tar czf ...` (flags without a hyphen) and bare `/home` `/etc` did not match the staging rule. Rule fixed.
3. `BEN-070` false positive: web command-injection rule matched `id && whoami` in a *process command line*. Web payload rules now skip
   process telemetry (events that carry a `command_line`).
4. `EVA-009` missed: a quoted executable path (`"C:\...\wevtutil.exe" cl "Security"`) defeated every command regex. Commands are now also
   evaluated with quotes / cmd `^` escapes / repeated whitespace removed.

After those fixes: recall 90/90, FP 0/70 on this corpus (the corpus the fixes were written against, so these are *fitted* numbers).

## Round 1: held-out set `holdout.yaml` (45 attacks HLD-*, 30 benign HLB-*)

Written after round 0 tuning, without iterating on rule regexes. **First-run result (no fixes yet):**

| Metric | Value |
|---|---|
| Attack recall | 33/45 = 0.733 |
| Benign false positives | 2/30 = 0.067 |
| Precision | 0.943 |

Misses: HLD-007 startup-folder copy, HLD-009 sudo GTFOBins shell escape, HLD-012 `fltmc unload SysmonDrv`, HLD-013 `net stop eventlog`,
HLD-016 MSBuild project from `\Users\Public`, HLD-021 `net view` share discovery, HLD-030 `sc stop MSSQLSERVER`,
HLD-031 `aws cloudtrail stop-logging` (CLI form), HLD-032 `aws iam create-access-key --user-name`, HLD-040 OGNL injection,
HLD-041 Spring4Shell-style classLoader access, HLD-044 SMB-signing registry change.
False positives: HLB-013 (`mysqldump` to /var/backups flagged as exfil staging), HLB-026 (a firewall **deny** matched the "exposed remote access" rule).
Wrong ATT&CK family: HLD-020 (Responder mapped to T1110/T1003, not T1557), HLD-029 (dd wiper mapped T1485, not T1561).

### Round 1 remediation (after seeing the held-out misses)

Product changes made because of the misses (not corpus edits): startup-folder path length, GTFOBins `sudo` shell escapes (new `TB-PRIV-006`),
`fltmc unload` and `net stop eventlog` in `TB-EVADE-002`, security-weakening registry changes (new `TB-EVADE-008`: SMB signing / WDigest / UAC / LSA),
MSBuild and other trusted-developer-utility proxy execution from user-writable paths (either argument order), `sc stop` of SQL/backup services,
CLI forms of cloud logging disablement (`aws cloudtrail stop-logging`, `gcloud logging sinks delete`, `az monitor diagnostic-settings delete`) and of IAM
privilege changes, network-share enumeration (new `TB-DISC-004`), Java expression-language/OGNL/class-loader injection (new `TB-WEB-010`),
database dumps are now suspicious only when written to staging locations or piped off-host (a local backup is not exfiltration),
firewall *deny* events no longer trigger the exposed-remote-access rule, ATT&CK ids added for Responder (T1557) and disk wipe (T1561).
Result on the (now fitted) corpus: 135/135 attacks, 0/100 benign false positives. These are no longer independent measurements.

## Round 2: held-out set `holdout2.yaml` (35 attacks HL2-*, 25 benign HB2-*; includes vendor-shaped payloads through the real adapters)

Written after Round 1 remediation. **First-run result (no fixes yet): 23/35 = 0.657 recall; 1/25 = 0.04 benign false positives; precision 0.958.**

Misses: HL2-005 ECS DNS tunnelling (rule keyed on a `network.dns` event type the ECS adapter does not emit), HL2-007 ECS authentication-failure
burst (no stateful rate detection over raw events), HL2-008 CEF IDS exploit signature, HL2-009 CEF firewall allow of RDP (action lives in the CEF
extension, not the event type), HL2-010 CloudTrail root usage via a read-only call (the adapter discards read-only calls), HL2-011 secret read by an
unfamiliar principal (needs a behavioural baseline), HL2-014 `cme` alias of crackmapexec, HL2-021 privileged container via Docker API JSON,
HL2-024 mass deletion via PowerShell, HL2-026 Cobalt Strike default named pipe, HL2-031 Java deserialisation gadget, HL2-033 server-side template injection.
False positive: HB2-017 (a Jenkins agent running a build script: `java` parent -> shell, and a path containing `/tmp/`).
Wrong ATT&CK family: HL2-025 AMSI bypass mapped to a download-cradle rule (T1059.001/T1105) instead of T1562.001.

### Round 2 remediation

Product changes made because of the misses: DNS-tunnel rule no longer depends on a vendor event type; firewall-allow detection reads the CEF `act` extension;
the CloudTrail adapter keeps Root-user calls and credential/secret reads (it used to drop every read-only call, which blinded Root-usage detection);
`cme`/`nxc` aliases; Docker-API JSON privilege flags; PowerShell recursive deletion of a drive; Cobalt Strike default named pipes;
Java deserialisation gadgets and server-side template injection (`TB-WEB-010`); IDS/IPS exploit signatures (`TB-NET-004`); aggregated authentication-failure
text (`TB-AUTH-009`); **stateful rate correlations over raw events** (`TB-COR-013` failure bursts, `TB-COR-014` password spraying by distinct accounts: the
platform previously could only chain events that had *already* alerted); AMSI bypass split from the download-cradle rule (`TB-EVADE-009`);
`java`/`node`/`ruby` removed from the web-server-parent list (CI agents spawn shells legitimately; documented in the rule's tuning note);
the `/tmp/` execution pattern now requires the path to be the thing executed; vendor payloads are normalised to canonical `raw_data` keys
(`app/ingest/normalize.py`) and full image paths no longer defeat `process_name` rules.
Accepted gap: HL2-011 (secret read needs a behavioural baseline).
Result on the (now fitted) corpus: 169/169 non-gap attacks, 0/125 benign false positives.

### Honest read of the three rounds

First-run recall on material written *after* tuning: 0.978 (round 0, fitted corpus), 0.733 (round 1), 0.657 (round 2, which also stressed the adapters).
The downward trend reflects that round 2 was harder (vendor-shaped payloads), not that quality fell. Even after remediation, expect a materially lower
recall on real, independent attacker behaviour than the 100% shown on this corpus, because every corpus was written by the rule authors.

### Correctness finding while building the demo campaign (not found by the benchmark)

Correlations were evaluated "when the last event arrives", but events are processed concurrently by independent workers, so two related
events could each miss the other's detections (or be reported twice). Fixed: each processor first persists its own detections, then evaluates
the whole entity group symmetrically, and a ledger (`correlation_hits`, migration 026) lets exactly one processor report each completion.
Verified with order-reversal tests and a two-thread test that forces the race window open. A related defect: `TB-COR-007` counted every tactic
of a multi-tactic technique, so one event could "span" several attack phases; it now counts one (primary) tactic per detection.
