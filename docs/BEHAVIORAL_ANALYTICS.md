# Behavioural analytics (UEBA)

Code: `backend/app/behavior/` (model, features, engine, config), `backend/app/services/behavior_service.py`, API `backend/app/api/v1/endpoints/behavior.py`,
schema `database/migrations/027_behavior_analytics.sql` (rollback `database/rollback/027_down.sql`), UI `frontend/src/pages/BehaviorPage.tsx`.

## What it is for, and what it is not

Signature rules cannot see an attacker who uses valid credentials and ordinary tools: a stolen account signing in from a new network at 03:00, a host that
suddenly sends 2 GB to a destination it never contacted, an admin action an identity has never performed. The behavioural layer compares each event with
(a) the entity's own history, (b) its peer group, and (c) the recent past, and reports a deviation only with evidence the analyst can read.

It does **not** treat every deviation as malicious. Most recorded anomalies are never alerts; a deviation alerts only when corroborated (below). It is a
second opinion that raises or fills in a case, never the only gate for a destructive action, and the response agent still needs human approval.

## Design choices (and why not something heavier)

| Need | Method | Why this and not a model |
|---|---|---|
| "Has this account/host done X before?" (networks, hosts, processes, ports, actions, resources) | Bounded categorical novelty sets with a **candidate -> promotion** step | Cheap, exact, explainable; a value joins the baseline only after >= 2 distinct days (or 5 sightings over >= 6 h), at most 20 new values per feature per entity per day. A one-off attacker session cannot teach the baseline that it is normal (anti-poisoning) |
| Unusual hour of login | Hour-of-day histogram smoothed +-2 h; probability < 0.02 is unusual | Handles shift workers without a time-zone assumption; needs >= 50 auth events before it speaks |
| Unusual size of a transfer or hourly egress | Robust z-score (median/MAD on log values) with hard floors (20 MB/h, 5 MB/flow) and hourly buckets with recurring-peak memory | Heavy-tailed data breaks mean/stddev; floors stop tiny absolute values alerting; a nightly backup that recurs is remembered as normal |
| Lateral breadth | Distinct hosts reached in an hour vs the account's history, floor of 6 hosts | A scanner and an admin sweep both look like this; breadth is only one family |
| "Is this normal for people like this?" | Peer groups by leader clustering on the profile (and an org-wide population row) | A first-time value shared by many peers (a new VPN range) is discounted (`peer_discount` 0.8); a value nobody else has is not |
| Combining signals | Max within a feature, noisy-or within a family (capped 0.95), noisy-or across families; alert needs >= 2 families, or one family >= 0.85 | One odd hour is not an alert; an odd hour **and** a new network **and** a first-time admin action is |
| Old evidence | Exponential decay, half-life 6 h | Unrelated oddities a day apart do not add up |

Not used: neural/autoencoder/isolation-forest models. With the small per-entity samples typical of a SOC tenant they are less explainable and not more accurate; the
choices above can be explained to an analyst in one sentence each and unit-tested exactly.

## Tenant isolation, cold start, persistence

* Every row is keyed by `organization_id` and deleted with the organisation; baselines are never shared across tenants, and the population/peer rows are per tenant.
* Cold start is safe: an entity needs >= 40 events and >= 3 days before its own baseline is trusted (`min_events`, `min_days`). Until then the layer only *learns*; the peer
  prevalence of a first-seen value can still produce a low-weight record (`cold_start_peer_prevalence`). A new host with a sudden exfil is therefore a **documented gap**, not a hidden one.
* Learning only from events that produced **no deterministic detection**, so an attacker's detected activity never becomes "normal".
* Profile writes use optimistic concurrency (`version` compare-and-swap, up to 8 attempts with jitter). Verified on PostgreSQL 16 with 12 racing writers: no lost update (`database/tests/test_workload.sh`).
* RLS is enabled with no end-user policy on `behavior_profiles`, `behavior_suppressions`, `behavior_settings`; `behavior_anomalies` is readable by analysts of the same organisation only. Baselines are statistical summaries; they never store command lines, payloads or secrets (`database/tests/test_security.sh`).
* Retention: `RETENTION_ANOMALIES_DAYS=90`, `RETENTION_BASELINE_DAYS=180` (`purge_behavior`).
* Redelivery of the same event is idempotent (the stored hit is returned, nothing is learned twice).

## Features (14)

`auth.source_net`, `auth.hour`, `auth.host`, `auth.breadth`, `priv.action`, `cloud.action`, `resource.access`, `proc.name`, `proc.pair`, `proc.exec_path`, `net.dest`, `net.port`,
`net.bytes_flow`, `net.bytes_out_hour`. Each maps to ATT&CK techniques (T1078, T1021, T1098, T1530, T1213, T1059, T1204, T1071, T1571, T1041, T1048) and to a rule id
`TB-UEBA-001..008` so the existing case, ATT&CK and reporting paths treat it like any detection. `GET /api/v1/behavior/features` lists them with weights.

## Explainability

An alert carries: the entity, the feature(s), observed value vs expected (e.g. "hour 03 has probability 0.004 for this account"), baseline maturity (events, days),
peer prevalence, the contributing families with their scores, the method, and whether it was suppressed (`budget | cooldown | suppression | learning`). The UI (Behaviour page)
shows the same fields; the triage panel marks the hit as `behavioral` versus `rule`.

## Noise control and tuning

* Alert budget: 3 per entity per day, 30 per organisation per hour; cooldown 24 h per feature family; re-alert guard 7 days.
* Analyst feedback: `PATCH /behavior/anomalies/{id}` with `confirmed`, `benign` (30-day suppression) or `expected` (teaches the baseline).
* Settings (`PUT /behavior/settings`, admin, audited): sensitivity `low | balanced | high` plus bounded overrides (e.g. `alert_score` 0.5-0.99, `min_events` 20-5000). Unknown or out-of-range keys are rejected, so the cold-start gate, corroboration and the alert budget cannot be configured away.
* `POST /behavior/learn` builds baselines from stored history; `POST /behavior/recluster` recomputes peers. Both run on the durable job queue.

## Validation (synthetic data only)

Scenarios (`validation/scenarios/behavior_*.yaml`) carry a warm-up history, then a deviation, with benign-but-unusual twins (travel, a new VPN range, month-end backup, on-call shift). A separate
noise simulation replays benign entities for 45-55 days. Results per split (see `docs/reports/evaluation-by-split.md`):

| Split | Attacks detected | Benign-unusual alerted | Alerts per 100 entity-days (benign simulation) | Gate |
|---|---|---|---|---|
| development | 9/9 | 0/18 | 0.173 | pass |
| tuning | 15/15 | 2/24 (8.3%) | 0.442 | pass (<= 0.10 FPR) |
| held-out (v4, frozen) | 15/15 | 2/24 (8.3%) | 0.262 | pass (<= 0.5 per 100) |

First run on the earlier held-out set (before the false-positive fixes): 3/24 benign alerted and 0.60 alerts per 100 entity-days (gate 0.5), both **failed**; they are recorded in
`validation/reports/history.md`. Noise has been reduced since (travel/new-VPN-range discounting, family corroboration, private-network weighting), but the simulation entities are generated, not real users: expect real-tenant noise to differ and
plan a shadow period (set `sensitivity: low`, review `/behavior/anomalies`, then relax).

Known limitations: baselines learn from whatever the tenant sends, so a tenant with sparse telemetry has sparse baselines; time-zone drift for travelling users is handled by smoothing, not modelled;
shared service accounts look like many users and will have wide baselines (suppress or let them mature); no per-entity seasonality beyond hour-of-day and recurring peaks.
