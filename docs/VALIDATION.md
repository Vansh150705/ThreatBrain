# Security validation lab

A reproducible way to measure what ThreatBrain actually detects, how often it is wrong, and where it is blind - and a release gate that fails when those
numbers regress. Everything here is **synthetic** and **safe by construction** (see section 5).

```bash
cd backend
python -m validation.runner --mode engine   --gate     # detection + correlation only (fast; the number gates are measured here)
python -m validation.runner --mode pipeline --gate     # the real FastAPI app: ingest -> queue -> worker -> detect -> correlate -> pipeline -> threats
# reports: backend/validation/reports/validation_report.{engine,pipeline}.{json,md}   history: reports/history.md
```

## 1. What is measured

| Corpus (`validation/scenarios/`) | Size | Purpose |
|---|---|---|
| `attacks.yaml` | 90 | Atomic-Red-Team-style procedures across 12 tactics, written in neutral telemetry titles so detection must come from behaviour |
| `holdout.yaml`, `holdout2.yaml` | 80 attacks + 55 benign | Written **after** tuning rounds without iterating on rule regexes (see section 3). Round 2 includes vendor-shaped payloads that go through the real Wazuh/ECS/CEF/CloudTrail adapters |
| `benign.yaml` | 70 | Benign **hard negatives**: legitimate admin/dev/CI/cloud activity that shares vocabulary with attacks (`net user alice`, `schtasks /query`, `mysqldump` to a backup volume, Jenkins spawning shells, firewall *denies*...) |
| `chains.yaml` / `chains_negative.yaml` | 14 / 7 | Multi-step campaigns that must / must not correlate (wrong order, other entity, outside window, below threshold) |
| `evasion.yaml` | 12 | Obfuscation probes. Misses are **published as known gaps**, not hidden; a gap that starts being caught must be un-flagged |

Metrics (per scenario, not per event): recall (attack scenarios detected), precision, false-positive rate on benign scenarios, ATT&CK-family mapping accuracy (do the hit rules map to the expected technique family),
campaign correlation recall and its negative twin, per-tactic recall, ATT&CK coverage (catalogue techniques with a rule / tested / detected), per-event latency (p50/p95/p99), and in pipeline mode end-to-end latency per scenario.
Gates live in `validation/gates.yaml` (recall >= 0.90, precision >= 0.95, benign FPR <= 0.03, mapping >= 0.80, campaign recall = 1.0, negatives = 1.0, engine p95 <= 25 ms). **Lowering a threshold to pass is not allowed; raising one is.**

## 2. Current result (commit at the time of writing; regenerate for the truth)

| | engine mode | pipeline mode |
|---|---|---|
| attack scenarios detected | 169 / 169 | 169 / 169 |
| accepted gaps (excluded, reason documented) | 1 (`HL2-011`: successful secret read needs a per-principal baseline) | same |
| benign false positives | 0 / 125 | 0 / 125 |
| precision / recall | 1.00 / 1.00 | 1.00 / 1.00 |
| ATT&CK-family mapping | 0.994 | 0.994 |
| campaigns correlated / near-misses held back | 14 / 14, 7 / 7 | same |
| evasion probes detected | 5 / 12 (7 open documented gaps) | same |
| per-event detection latency | p50 0.6 ms, p95 1.3 ms, p99 1.7 ms | end-to-end per scenario p50 ~15 ms, p95 ~40 ms (in-memory DB, scripted LLM) |

**Do not read 100% as "it detects everything".** The corpus the rules were tuned on will always look perfect (see section 3). Evasion detection is 5/12 and the open gaps are listed in the report.

## 3. Honest history: how the numbers were produced

`reports/history.md` is append-only. Summary of what each round revealed:

| Round | First-run result on material written *after* the previous tuning | What it found |
|---|---|---|
| 0 - initial corpus | 88/90 attacks (0.978), 1/70 benign false positives | event flattening stopped at depth 6 (CloudTrail CIDRs invisible), `tar czf` flags, a web-injection rule firing on a process command line, quoted executable paths defeating every command rule |
| 1 - held-out `holdout.yaml` | **33/45 (0.733)**, 2/30 false positives | sudo GTFOBins escapes, `fltmc unload`, `net stop eventlog`, MSBuild proxy execution, CLI forms of cloud logging/IAM changes, share discovery, OGNL/Spring injection, SMB-signing registry change, mysqldump flagged as exfiltration, firewall *denies* flagged as exposure |
| 2 - held-out `holdout2.yaml` (adapters included) | **23/35 (0.657)**, 1/25 false positives | DNS-tunnel rule keyed on a vendor event type, no stateful failure-rate detection (added `rate` correlations), CEF action in an extension, **CloudTrail adapter discarding Root-user read calls**, `cme` alias, Docker-API JSON flags, Cobalt Strike pipes, Java deserialisation, SSTI, a Jenkins false positive |
| after each | the fixes above, each tied to a product change (never to editing the corpus) | |

Two further defects were found by building features, not by the benchmark: correlation was order/race-dependent with concurrent workers (fixed with symmetric evaluation + a ledger) and `TB-COR-007` counted every tactic of a multi-tactic technique.
The honest reading is the *first-run* column: **65-75% detection on freshly written attack material, ~4-7% false positives on freshly written benign material**, before remediation. Expect real-world recall against independent adversary behaviour to be
materially lower than the post-remediation 100%, and your false-positive rate to depend on your environment.

## 4. Limitations (also printed in every report)

1. Scenarios were written by the people who wrote the rules. They follow public procedures but are **not an independent benchmark**.
2. All telemetry is synthetic event data; no real malware, credentials or exploitation. No command in a scenario is ever executed.
3. The benign set is small. Production false-positive rates must be measured on your own telemetry (run a rule in `draft`/dry-run against exported logs before enabling).
4. LLM quality is not measured: pipeline mode uses a scripted model and an in-memory database. No live Groq/Supabase behaviour is verified. Token counts are reported as unknown rather than invented.
5. Detection is per event plus windowed correlation; there are no statistical baselines or UEBA.
6. Coverage is relative to a curated 167-id ATT&CK subset, not the full framework; reconnaissance has no scenario.

## 5. Safety model for emulation

* Scenarios are **event data and strings only**. The lab has no code path that passes a scenario command to a shell (a test greps the lab for `subprocess`/`os.system`/`shell=True`; `safety.assert_text_only` refuses by design).
* Anything that sends data over a network is limited by `validation/safety.py::assert_lab_target`: loopback is allowed; any other host requires **both** `LAB_AUTHORIZED=1` and a `LAB_ALLOWLIST` (hosts/CIDRs) match, and public
  internet addresses are refused even then. Unit-tested (private-but-unauthorised, authorised-without-allowlist, outside the allowlist, public IP, bad schemes).
* No destructive actions, no credential access, no malware samples; the "EICAR" scenario uses the standard harmless antivirus test string as data.
* If you extend the lab to execute real procedures, do it only on isolated assets you own and are authorised to test, through the allowlist, and never from this repository's CI.

## 6. Adding a scenario

Add it to the right file with neutral titles, run `--mode engine`, and if it is missed or alerts when it should not, **fix the rule (or document the gap with a reason), do not edit the scenario to pass**. Every new rule needs inline tests *and* at
least one scenario. Fresh material for a new held-out round should be written before looking at the rules and its first-run result appended to `reports/history.md` before any fix.
