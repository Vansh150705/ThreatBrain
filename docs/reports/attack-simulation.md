# Final attack-simulation report

Read this first: **nothing in this report is a live attack and none of it is independent of the authors in the strong sense.** Every "attack" is a *telemetry scenario*: the command line,
HTTP request, cloud-audit record or flow that a technique would produce, fed through ThreatBrain's real ingest -> normalisation -> detection -> correlation -> (optionally) agent pipeline. No payload was
executed, no malware, credential theft, exfiltration or destructive action was performed, and no network target was touched. This is the safe-by-construction form of adversary emulation; it measures
detection logic, not an EDR's ability to observe real execution.

## Sources and independence

| Source | What it is | Who labelled it | Split use |
|---|---|---|---|
| Hand-written scenarios (`attacks.yaml`, `holdout*.yaml`, `heldout_v3*.yaml`, `heldout_v4*.yaml`) | attacks and difficult negatives in vendor-shaped events, incl. CloudTrail/CEF/ECS/Wazuh payloads through the real adapters | rule authors (same team) | development, tuning, held-out |
| Atomic Red Team (`art_derived.yaml`, 1,187 procedures covering 158 technique ids at a pinned commit; MIT, Red Canary) | the commands from ART test definitions, **as text only** | ART authors (technique id, platform) - independent of the rule authors | split by `sha256(auto_generated_guid)` parity: even = tuning, odd = blind. Chosen before seeing detections |
| LOLBAS (`external/lolbas_derived.yaml`, 296 procedures) | documented living-off-the-land use-cases | LOLBAS project (GPL-3, **downloaded at evaluation time, not committed**) | same parity split |
| Adversarial variants (`adversarial_unseen.yaml`) | obfuscation of known behaviours (cmd, PowerShell, POSIX, web), with benign look-alikes | rule authors | consumed -> tuning |
| Multi-stage campaigns (`chains*.yaml`, `heldout_v3/v4_chains.yaml`) | ordered kill-chain sequences, plus near-miss sequences that must stay quiet | rule authors | development, tuning, held-out |
| Behavioural scenarios (`behavior_*.yaml`) | a history window then a deviation, plus benign-unusual twins | authors | development, tuning, held-out |

MITRE Caldera was **not** used: there was no authorised, isolated lab with Caldera agents in this environment, and the constraint is that emulation may run only against explicitly authorised, isolated assets. The safety model (`validation/safety.py`: loopback by default, allow-listed host plus `LAB_AUTHORIZED=1` otherwise, telemetry text only) and the collector pipeline are ready for it; running Caldera operations in a disposable lab and feeding their telemetry through the collector is an open item, not a result.

Held-out protocol: `datasets.yaml` (every scenario in exactly one split), `FROZEN.json` (sha256 per frozen set, checked in the release gate), blind sets reported as aggregates only, per-scenario held-out detail archived separately. Sets whose detail was
used to fix rules were **moved to the tuning split** and their old numbers are kept in `history.md` as first-run records. `python -m validation.leakage --gate` checks template/near-duplicate leakage between rules' inline tests and the blind sets (ART: 14.8% near-duplicates of rule-test commands, 2 exact; LOLBAS 4.8% / 0 - gate passes, but the 2 exact matches mean ART blind numbers are very slightly flattered).

## Results by split (never pooled; full tables in `evaluation-by-split.md`)

| Split / corpus | Attack recall (any hit) | High-signal tactics | Benign FP | Notes |
|---|---|---|---|---|
| development, hand-written (90 attacks) | 100% | 100% | 0/70 | tuned against; regression guard only |
| tuning, hand-written (186) | 98.4% | 98.3% | 0/106 | 3 missed, 4 detected only as signals |
| tuning, ART tuning half (580) | 44.8% | **58.2%** | n/a | gate 60% **FAILED** |
| tuning, LOLBAS tuning half (149) | 73.8% | 74.3% | n/a | |
| tuning, adversarial variants (32) | 100% | 100% | 0/9 | consumed set |
| **held-out v4, hand-written (39)** | **94.9%** | 94.7% | 0/37 (first run: 4/37) | FP figure not independent after fixes |
| **held-out, ART blind half (607)** | **40.7%** | **46.4%** | n/a | gate 60% **FAILED** |
| **held-out, LOLBAS blind half (147)** | **55.8%** | 56.2% | n/a | |
| campaigns: dev 14/14, tuning 11/11, held-out 7/7 | | | near-misses quiet: 7/7, 6/6, 3/3 | evidence ids correct 12/14, 8/11, 5/7 |
| behavioural: dev 9/9, tuning 15/15, held-out 15/15 | | | benign-unusual alerted 0/18, 2/24, 2/24 | |

The headline for an enterprise buyer is the blind ART/LOLBAS rows, not the tuned rows: on ordinary adversary procedures the authors did not write rules for, the rule set alerts on roughly **40-56%**, and on the high-signal
tactic subset on **46%**. Tactic-level blind ART recall ranges from 10% (collection, 1/10) and 29% (defense evasion, 29/99) to 72% (credential access, 39/54).

Mapping and severity (held-out hand-written, detected attacks only): ATT&CK technique-family mapping 78.4% (gate 70%), severity within one level of the analyst label 94.6%, under-rated by 2+ levels 5.4% (2/37).

## Time-to-detect

* Rule hits: evaluated inline at ingest; engine p50/p95 per scenario 0.6/2.1 ms (development), 3.5/19.5 ms for ART scenarios (more events per scenario).
* Campaign correlation: median time to the *first* alert is 0 minutes (the first stage alerts on its own); the campaign alert itself fires on the last-arriving stage, i.e. after the median first-to-last span of 15 min (development), 60 min (tuning), 25 min (held-out) of simulated event time.
* Behavioural: median 5-7 hours from the first deviation to an alert across splits (corroboration needs a second family, which the scenarios place hours apart).
* Real pipeline sample (40 random scenarios, in-memory database, scripted model): ingest -> detection p50 26.6 ms, ingest -> investigation complete p50 26.9 ms, 24/24 agent runs completed, 0 failed. This is **platform overhead only**; real LLM latency and token cost are not measured.

## Robustness experiments

| Experiment | Result |
|---|---|
| Metamorphic retention (semantics-preserving mutations of detected attacks) | 0.997 (development+tuning), 1.0 (held-out) |
| Chains with reordered events | 1.0 still correlate |
| Chains with duplicated events | 1.0 still correlate, no double alert (exactly-once ledger) |
| Command lines truncated to 120 chars | 99.5% of detections retained |
| username / asset / process name missing | 99.2% retained at single-event level |
| Prompt injection in events and intel (agent evaluation, 6 variants x scripted injection-following model) | 0 obeyed; see `AGENT_EVALUATION.md` |
| Rule-engine ReDoS guard | rule loader rejects nested quantifiers and unbounded wildcards (`engine.py`; Sigma imports pass the same guard, `test_sigma.py`); decoders are length-bounded |

Not covered by any experiment: real low-and-slow campaigns over days with benign noise at production volume, distributed multi-source attacks across tenants' real log pipelines, an attacker who knows the rule set and tunes to it,
telemetry gaps larger than the field-loss experiments, and anything requiring host sensor visibility (memory, API calls, kernel events).

## Open items to make this report stronger

1. Run Caldera / Atomic Red Team **execution** in an isolated authorised lab with the collector, and compare real telemetry to the text-only scenarios.
2. Have people who did not write the rules author a new held-out set and freeze it before any run.
3. Add EDR-style telemetry adapters for the classes that are unreachable from a command line (process injection, `T1055`; credential dumping variants; network sniffing).
