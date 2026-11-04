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

---

# Round 3 (enterprise phase 2): independent datasets, multi-split evaluation

Honest-measurement changes made BEFORE any of the numbers below were seen:
* `validation/datasets.yaml` assigns every scenario to one split (development / tuning / held-out). Results are never pooled.
* Held-out sets were written **without consulting `rules.yaml`/`correlations.yaml`** and frozen by hash in `validation/FROZEN.json` (committed in `3518c25`,
  before the first evaluation): 94 hand-written attacks (HO3), 51 difficult negatives (HB3), 17 campaigns (HC3), 41 previously-unseen obfuscation variants and
  look-alikes (ADV), 39 behavioural scenarios (BEH-H) and the **blind half of Atomic Red Team** (607 tests; the other 580 are the tuning half). The ART split is
  `sha256(auto_generated_guid)` parity, fixed before evaluation, so nobody can choose which tests count.
* ART labels (technique ids) and command strings come from Red Canary's authors, not from this project. 163 technique files were imported (12 requested ones do not exist upstream and were skipped).
* Gate thresholds (`validation/gates_v2.yaml`) were fixed before the held-out run.

## First run on the frozen held-out sets (no remediation yet) - the official independent measurement for this round

| Held-out set | Result | 95% CI |
|---|---|---|
| Hand-written attacks (HO3, 94) recall | **69/94 = 73.4%** | 63.7-81.3% |
| Difficult negatives (HB3, 51) false-positive rate | **9/51 = 17.6%** | 9.6-30.3% |
| Detected attacks mapped to the right technique family | 92.8% | |
| Severity within one level of the analyst label / exact | 97.1% / 68.1% (0 under-rated by 2+) | |
| Unseen obfuscation variants (ADV) detected | 29/32 = 90.6% (0/9 benign look-alikes alerted) | 75.8-96.8% |
| **Atomic Red Team blind half, all tactics** | **172/607 = 28.3%** | 24.9-32.0% |
| **Atomic Red Team blind half, high-signal tactics** | **108/334 = 32.3%** | 27.5-37.5% |
| Campaign correlation (HC3) | 5/11 = 45.5% (6/6 near-misses stayed quiet; evidence ids correct for 2/5) | 21.3-72.0% |
| Behavioural attacks detected (BEH-H) | 15/15 | 79.6-100% |
| Behavioural benign scenarios that alerted | 3/24 = 12.5% | 4.3-31.0% |
| Behavioural alert volume on a 50-day benign simulation | 0.60 alerts / 100 entity-days (gate 0.5) | |

Gates failed on this first run: held-out attack recall (0.734 < 0.80), held-out benign FPR (0.176 > 0.05), ART high-signal recall (0.323 < 0.60),
campaigns (0.455 < 0.80), behavioural benign FPR (0.125 > 0.10), behavioural noise (0.60 > 0.5). They stay failed in this history; the sections below
say what was changed and what the re-measurement was.

What this says: the 100% on the tuned corpus is not evidence of real-world coverage. Against an independently authored corpus of ordinary adversary
procedures the rule set detects roughly a third of high-signal tests. The largest classes of miss (from the TUNING half only) are registry modification (T1112),
ingress tool transfer (T1105), credentials in files (T1552.001), decode/deobfuscation (T1140), UAC bypass (T1548.002), proxy execution through signed binaries
(T1218.*), remote-access tools (T1219) and secure deletion (T1070.004).

Protocol from here: the held-out detail written in this run is archived in `reports/baselines/` for the record. Anything fixed using that detail turns the
set into a TUNING set (it is moved in `datasets.yaml` and re-frozen with a reason). A fresh frozen held-out set (v4) plus the never-inspected ART blind half
are used for the re-measurement.
