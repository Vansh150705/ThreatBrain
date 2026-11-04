# Detection-gap remediation report

Scope: the weaknesses left by the previous release report (7 of 12 evasion probes missed; the 100% on the tuned corpus not being evidence of
real-world coverage), what was changed, and what is still open. Numbers are copied from `backend/validation/reports/` (append-only
`history.md`, `evaluation.json`); splits are never pooled.

## 1. The seven missed evasion probes: root cause and general fix

Each miss was classified by the layer that failed. The fix is a *class* fix, tested on unseen variants and benign twins, not a string added for the probe.

| Probe | What the attacker did | Failing layer | General fix | Now caught by |
|---|---|---|---|---|
| EVA-001 | `('i'+'ex')`, `('Down'+'loadString')` string splicing | **normalisation** (rules saw the spelling, not the meaning) | `app/detection/deobfuscate.py` folds PowerShell concatenation, `-f` format strings, `[char]` chains, backticks; folded text is evaluated as an extra *view* | TB-EXEC-002, TB-EXEC-017 |
| EVA-002 | netcat renamed `svc-helper ... -e /bin/sh` | **rule** (anchored on the tool name) | rule matches the *behaviour shape* (host, port, `-e` shell), not the binary name; telnet-pipe variant added | TB-EXEC-003 |
| EVA-003 | defender off via `reg import x.reg` from a public folder | **telemetry/rule** (the setting is in a file the command line only references) | rule on `reg import` of a file from user-writable/staging locations (the reference is what is observable) | TB-EVADE-010 |
| EVA-004 | clear logs through the .NET `EventLogSession.ClearLog` API | **rule** (only `wevtutil` / `Clear-EventLog` known) | API-level patterns added next to the CLI ones | TB-EVADE-001 |
| EVA-005 | credential dumper with innocuous name `update-helper.exe --target 612 --out x.bin` | **rule** (name-based) | argument-shape rule: process-id target + dump output to a temp path, independent of binary name | TB-CRED-005 |
| EVA-006 | bulk exfil over HTTPS with no tool signature | **engine** (single event, no baseline: undetectable by signature) | behavioural analytics: per-host hourly byte volume vs the host's own history and peers | UEBA only, when a baseline exists (BEH-A04/A08). The original one-event probe stays flagged `known_gap` |
| EVA-011 | double URL-encoded traversal `%252e%252e%252f` | **normalisation** | decode up to three layers, plus overlong UTF-8 and Unicode look-alikes of `/ . \` | TB-WEB-005 |

Why EVA-006 is not "closed": a single flow record with no history cannot be told from a backup. Claiming otherwise would be gaming the probe. The UEBA layer
detects it when the host has a mature baseline (>= 40 events and >= 3 days); a brand-new host is a documented cold-start gap.

### Evasion suite expansion

`evasion.yaml` (12 probes) plus `adversarial_unseen.yaml` (32 variants in cmd / PowerShell / POSIX / web families, each family with benign look-alikes):
case, whitespace, quoting, caret, `${IFS}`, ANSI-C `$'..'`, backtick, `-f` format, `[char]`, base64 UTF-8 and UTF-16LE (`-enc`), nested URL encoding, overlong UTF-8,
mixed-case `${lower:j}` lookups, SQL comment splicing, `.exe` suffix variants. Also covered by `validation/mutations.py` (metamorphic): every
detected attack is re-run through semantics-preserving mutations and must still be detected (retention 0.997 dev+tuning, 1.0 held-out), and benign scenarios
through cosmetic mutations must stay quiet (0 false positives; encoding wrappers are excluded from the benign mutation set *by design* because a base64 wrapper of anything is suspicious).
Degraded-telemetry experiments: reordered and duplicated chains still correlate (1.0), commands truncated to 120 chars keep 99.5% detection, loss of username/asset/process-name keeps 99.2%.

Safety: nothing is executed. The decoders are string rewriting bounded by `MAX_LEN` and work per event; rule regexes are validated against ReDoS (no unbounded `.*`, no nested quantifiers).

## 2. Independent measurement and what it showed

The tuned corpus reaching 100% was never accepted as evidence. A frozen, never-tuned set was written and hash-frozen (`FROZEN.json`, checked by `freeze.py --check` in the release gates).

| Held-out measure (first run, before remediation) | Value |
|---|---|
| hand-written attacks | 69/94 = 73.4% |
| difficult negatives false-positive | 9/51 = 17.6% |
| Atomic Red Team blind half, high-signal tactics | 108/334 = 32.3% |
| campaigns | 5/11 = 45.5% |

After remediation on the tuning side only, on the next frozen set (v4, first run, rules as of 1bfcb65): attacks 94.9% (37/39), false positives **10.8% (4/37)**, ART blind high-signal **46.4%
(155/334)**, campaigns 7/7. The four v4 false positives were fixed after reading their rule ids, so the current 0/37 is **not independent**; the first-run row is.

## 3. Still open (gates that remain failed)

| Gate | Value | Threshold |
|---|---|---|
| `tuning.art_high_signal_recall` | 0.582 | >= 0.60 FAILED |
| `heldout.art_high_signal_recall` | 0.464 | >= 0.60 FAILED |

Atomic Red Team contains many tests whose telemetry is a bare administrative command. The largest remaining classes are system/network discovery
(T1018, T1049, T1016, T1007, T1033, T1012), network sniffing, WMI use, obfuscated files, process injection and several credential-dump variants. Alerting
on them from the command line alone would trade recall for false positives, so discovery is `signal`-tier (recorded and usable by correlation; never opens a threat alone). These
need context the synthetic command lines do not carry, or EDR telemetry (API calls, memory access), which the platform does not receive.
LOLBAS-derived recall (a GPL-3 dataset downloaded at evaluation time and not committed): 73.8% tuning, 55.8% blind.

The thresholds were not lowered. The `heldout` ART number is the honest estimate for "ordinary adversary procedures the authors did not write rules for".
ATT&CK coverage (rules mapped to techniques): 83 of 228 parent techniques, 156 of 715 including sub-techniques (`docs/reports/attack-coverage.md`).

## 4. How to reproduce

```bash
cd backend
python -m validation.freeze --check        # held-out sets unchanged since freezing
python -m validation.evaluate --gate --pipeline-sample 40
python -m validation.leakage --gate        # near-duplicate / template leakage between rules and the held-out sets
python -m validation.report                # docs/reports/evaluation-by-split.md
```
