# False-positive analysis

Sources: `backend/validation/reports/history.md`, `evaluation.json`, `baselines/`, `docs/reports/evaluation-by-split.md`. Benign scenarios are synthetic, written to look like administration
(difficult negatives) and each rule carries inline benign-twin tests. None is real customer traffic, so these rates are *lower bounds on what a real tenant will see*.

## Measured rates (alerts only; signal-tier hits are counted separately)

| Split | Benign scenarios | False positives | Rate | Gate |
|---|---|---|---|---|
| development | 70 | 0 | 0.0% (95% CI 0-5%) | <= 2% pass |
| tuning (hand-written + adversarial look-alikes) | 106 + 9 | 0 + 0 | 0.0% | <= 3% / 5% pass |
| held-out v3, **first run**, before remediation | 51 | **9** | **17.6%** | <= 5% **failed** at the time |
| held-out v4, **first run** (rules as of 1bfcb65) | 37 | **4** | **10.8%** | <= 5% **failed** at the time |
| held-out v4, after fixing those four | 37 | 0 | 0.0% | pass, **not independent** (rule ids were read after the first run) |
| benign mutation (cosmetic respellings of benign scenarios), dev+tuning / held-out | n/a | 0 / 0 | 0.0% | <= 3% pass (the mutation set excludes encoding wrappers by design) |

Signal-tier hits on benign scenarios (a recorded low-confidence behaviour that never opens a threat): 1 in the tuning split, 1 in the held-out split, 0 in development.

The point of the two "first run" rows: the previous release showed 0 false positives on its own corpus and the independent set found 17.6%. That was the real state of the rules.

## What the false positives were (held-out v3 first run, now tuning data)

| Scenario | Rule that fired | Why it was wrong | Fix class |
|---|---|---|---|
| backup agent service registered from `Program Files` (`sc create`) | TB-PERSIST-004 | service creation flagged regardless of image path | trusted install locations are not suspicious; keep user-writable paths |
| nightly backup `schtasks /create ... C:\ops\backup.cmd /ru SYSTEM` | TB-PERSIST-002 | any SYSTEM scheduled task | require a user-writable or staged payload path, not an ops directory |
| vendor installer `reg add ...\Run /d "C:\Program Files\Zoom\..."` | TB-PERSIST-004 | any Run key | payload under `Program Files`/`Windows` is expected |
| helpdesk `net user jsmith ... /domain` (password reset) | TB-DISC-001 | account command treated as discovery | now `signal`-tier, and only for enumeration forms |
| admin `nltest /domain_trusts` | TB-DISC-001 | discovery tool used daily by admins | `signal`-tier (recorded, usable by correlation, no threat) |
| `openssl enc` encrypting `/var/backups` with a key file | TB-IMPACT-002 | encryption tool = ransomware | narrowed away from single encryption-tool invocations (see the rule's inline benign-twin tests) |
| developer `ssh -N -L 5432:db:5432 jump` | TB-LAT-004 | port forwarding = tunnelling | rule narrowed to the administrative remote-access tunnelling shape (see the rule's inline tests) |
| cron installed by Puppet (`crontab /etc/cron.d/puppet-managed`) | TB-PERSIST-002 | cron persistence | config-management paths and parents excluded |
| developer `ssh-copy-id` to a staging host | TB-CRED-003 | key insertion = credential access | adding **own** key through ssh-copy-id is a normal workflow |

The exact benign twins that now guard each rule are its inline `tests:` in `backend/app/detection/rules.yaml`. Every fix follows the same discipline: narrow the *anchor* (path class, parent process, destination class) rather than delete the rule; add the benign twin as an inline rule test and keep the attack
variant as a positive test, so recall on the attack side does not regress (development recall stays 1.0; tuning 0.984).

## Why this is not "solved"

* False-positive risk is traded against recall explicitly. Discovery commands (T1018, T1049, T1016, T1007, T1033, T1012) are a large share of ART misses; they are `signal`-tier because alerting on them from the command line
  would reintroduce the false positives above. That is the reason `heldout.art_high_signal_recall` is still failing instead of being "fixed" by loosening rules.
* The held-out sets are small (37 and 51 benign scenarios): a 0% observed rate has an upper 95% bound of ~9% (n=37). Do not read "0%" as "below 1%".
* The rules cannot know the tenant's normal. The tuning aids are: per-rule `tuning` guidance, rule overrides (per-org severity/disable, audited), the Detection Engineering agent (drafts only, verified by replay against real FP/TP samples), suppressions with expiry, and the behavioural layer's analyst dispositions.

## Behavioural analytics noise

Benign-entity simulation, alerts per 100 entity-days: development 0.173 (3,476 entity-days), tuning 0.442 (6,794), held-out v4 0.262 (9,908); gate <= 0.5. The *first* run on the earlier held-out set was 0.603 and failed.
Benign-but-unusual scenarios (travel, new VPN range, month-end backup, on-call): 0/18 alerted (development), 2/24 (tuning), 2/24 (held-out v4); gate <= 10%. The two that alert are `auth_location` combinations at the
edge of corroboration; they are visible in `backend/validation/reports/evaluation.json` under `results.splits.tuning.behavior.failed`.
All 'alerts' in the simulations are `auth_location` / `auth_time` families, i.e. sign-in anomalies; real tenants will add process/network/volume noise that the generated entities do not exercise.

Expected analyst load at 0.26 alerts per 100 entity-days: roughly 2.6 behavioural alerts a day for 1,000 active accounts/hosts, before the per-entity (3/day) and per-organisation (30/hour) budgets. Real volume depends on tenant churn.

## Recommended rollout to keep noise down

1. Shadow period: behavioural `sensitivity: low`, review `/behavior/anomalies` and mark `benign` / `expected` (feeds suppressions and baselines).
2. Review the top-5 firing rules weekly with `/detection` stats; add overrides for the tenant's known tools (backup agents, config management, jump hosts) rather than editing shipped rules.
3. Treat `signal`-tier detections as correlation fuel, not alerts, until a campaign rule fires.
4. Keep a labelled sample of closed alerts; the `GET /behavior/status` precision of past alerts and the detection engineering agent's replay gate use it.
