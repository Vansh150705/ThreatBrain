# Audit report

Two phases: the **first audit** (sections below, up to "Capabilities added") and the **enterprise phase** (appended). Each finding was confirmed by a failing test or a reproduction before it was fixed.

Baseline (before changes): collector 101 tests passing; frontend `lint` 0 errors / 37 warnings, build OK; **backend had no automated tests** (only live-API smoke scripts), imported and served `/health`. Everything below was found by reading the code and then confirmed with a failing test or a reproduction where practical.

## Defects fixed

### Security
| # | Finding | Fix |
|---|---|---|
| S1 | `/threats/geo` looked IOCs up **without an organization filter**: one tenant's geo data leaked into another's map. | Filtered by org; regression test (`test_geo_endpoint_does_not_leak…`). |
| S2 | Response agent let the **LLM choose the firewall/account target** with no check: a prompt-injected event could queue "block 8.8.8.8" or "disable the CEO". | Targets must appear in the incident's own evidence; CIDR breadth capped; allow-listed action types (`test_prompt_injection_cannot_redirect…`). |
| S3 | Auto-execute playbooks were reported as **`executed` although nothing ran**; queued approvals were labelled `simulated`. | Server never executes; statuses are `recommended` / `simulated` / `skipped(reason)`; `executed` only via executor report. |
| S4 | Unhandled errors returned `str(exc)` (debug default was **on**); 503s, `/health/db`, login/signup/copilot errors leaked driver/Supabase/LLM text. | Generic bodies; debug off by default and refused in production; tests assert no internals leak. |
| S5 | `decode_supabase_jwt` exposed `verify_signature=False` / `verify_exp=False` switches. | Removed; signature, expiry, audience and required claims are always enforced (forged, expired, `alg=none` tested). |
| S6 | No rate limiting (settings existed, unused); open signup + LLM endpoints = cost/DoS surface. | Sliding-window limiter: global, auth (10/min), LLM (20/min); `ALLOW_PUBLIC_SIGNUP`; trust of `X-Forwarded-For` is opt-in. |
| S7 | Approval decision/execution report were check-then-update (**race**); execution audit hardcoded `block_ip`. | Conditional updates (409 on loser); audit uses the real action type. |
| S8 | Users without an organization crashed ~10 endpoints with a 500 (`UUID(None)`). | Single `require_*` gate returns 403 `no_organization`. |
| S9 | Collector/executor needed a **full user password** on disk. | Scoped, revocable API keys (`ingest`, `executor`); keys cannot read data, approve, or mint keys. |
| S10 | Executor: `usermod -L <name>` allowed option injection (`-h`); IPv6 attackers went to IPv4 `iptables`; a failed report crashed the loop. | Names cannot start with `-`, `--` separator, `ip6tables`, resilient reporting. |
| S11 | CORS allowed all methods/headers with credentials; no security headers; unvalidated IP strings reached INET columns and feed URLs; unbounded `raw_data`. | Explicit CORS lists; headers (+HSTS in prod); IP/hash/criticality validators, 60 KB cap. |
| S12 | Prompt data was concatenated raw; copilot snapshot (attacker-controlled titles) too. | `<untrusted_data>` fencing with tag stripping, system-prompt rule, structured outputs. |
| S13 | Hard-coded sample data was inserted into **every** new workspace untagged. | Optional (`SEED_DEMO_DATA`), tagged `sample-data`. |

### Correctness / reliability
| # | Finding | Fix |
|---|---|---|
| C1 | `async def` endpoints called **blocking** LLM/DB code: one 15 s pipeline froze the whole server. | Sync endpoints (thread pool); background execution; test proves `/health` answers while an LLM call is in flight. |
| C2 | Investigation re-grouped threats **already in incidents**, creating duplicate incidents on every run; incident `source_ips`/MITRE/counters were never populated. | Only unlinked threats; shared aggregate refresh; deterministic IP correlation. |
| C3 | Forensics timeline and playbook runs were never saved although the UI tab reads them. | Persisted on the incident. |
| C4 | Pipeline ran all stages for benign events, sequentially, with no timeouts and `str(exc)` errors. | Stops when nothing is promoted; response/forensics/compliance in parallel; per-stage timeout, retry only for schema-invalid output, safe errors, trace. |
| C5 | LLM client: no timeout, retried non-retryable 4xx, hard-failed on fenced JSON. | Timeout, retry only transient errors, fence/prose-tolerant parse + one repair, concurrency cap. |
| C6 | No de-duplication: one brute-force campaign = a new threat, incident and 6 LLM calls per event. | Fingerprint de-dup (verified: second event spends 0 tokens). |
| C7 | Soft-deleted rows appeared in lists, detail and stats. | Filtered everywhere. |
| C8 | `requirements.txt` was UTF-16/CRLF and listed unused heavy deps (langchain ×3, passlib, bcrypt, cryptography). | UTF-8, trimmed; verified in a clean venv. |
| C9 | Migration 017 seeds rows referencing the demo org: **fails on a fresh database** (FK). | Conditional insert; whole chain verified on PostgreSQL 16 (`database/verify_migrations.sh`). |
| C10 | Collector lost events on any API failure and mishandled log rotation/truncation. | Retry+backoff, durable bounded spool with replay, rotation-safe tail. |
| C11 | Settings `JWT_*`, `DISCORD_*`, `RATE_LIMIT_*` were unused. | Rate limit and Discord implemented; dead JWT settings removed. (`RESEND_*`, `N8N_*` remain declared but unused; no email/n8n integration exists.) |
| C12 | README claimed Hunt "runs proactively on a schedule" but no scheduler existed; `LICENSE` was referenced but missing. | Opt-in scheduler (`HUNT_INTERVAL_MINUTES`); LICENSE added. |

## Capabilities added
Detection rule engine · alert de-duplication · deterministic incident correlation · rules-only degraded mode · verdict reconciliation · traced, parallel orchestrator with durable `pipeline_runs` · Log Analysis agent with verified evidence · multi-feed threat intel · SIEM adapters (Wazuh, ECS, CEF, CloudTrail, Splunk, generic) · async ingest · API keys · case management (status/owner/priority/notes/timeline) · SOC metrics · Discord alerts · optional hunt scheduler · console pages (Pipelines, Log analysis, Settings, case panel, triage panel, SOC metrics) · Docker, compose, CI.

## Not done / residual risk (first audit; see the enterprise phase for what changed since)
* Live Supabase, Groq, feed and Discord calls, Docker image builds and the executor on a real firewall were **not exercised** in the build environment (see README -> Verification status).
* ~~HS256-only JWT verification~~ - asymmetric Supabase keys and an external OIDC IdP are now verified via JWKS (locally generated keys only; not a live IdP).
* ~~In-memory background pool~~ - background work is now a durable PostgreSQL queue with leases, retries and a dead-letter state. Rate limiting is still per process.
* ~~No automated frontend tests~~ - vitest component tests and a Playwright browser suite are in the repo.
* The rule set remains a starting point; detection coverage is a continuing programme (see VALIDATION.md for measured numbers and open gaps).
* `backend/scripts/test_*.py` are legacy live-API smoke scripts (they hit a deployed backend); they are not part of the test suite.

---

# Enterprise phase

Scope: durable ingestion, detection platform, identity hardening, operations, validation lab, adversarial testing, frontend, deployment. Same method: reproduce, fix, regression-test. Items are
grouped by how they were found, because *how* a defect was found says what kind of test was missing.

## Found by testing against real PostgreSQL
| # | Finding | Fix |
|---|---|---|
| E1 | The IOC cache upsert (`ON CONFLICT (organization_id, ioc_type, normalized_value)`) could never succeed on a real database: the unique index from migration 010 is **partial** (`WHERE deleted_at IS NULL`), which `ON CONFLICT` cannot target. The error was swallowed, so every IOC-cache write silently failed in production. | Migration 025 replaces it with a full unique index (after de-duplicating soft-deleted rows); re-verified with the real upsert. |
| E2 | The event idempotency index would have had the same flaw (partial). | Created non-partial. |
| E3 | `restore.sh` (first version) used `pg_restore --clean`, which cannot run against a live Supabase-shaped schema (functions with dependent triggers on `auth.users`). | Rewritten as an atomic data-only reload in one transaction; tested incl. failure-leaves-data-untouched and tamper refusal. |
| E4 | `backup.sh --verify` printed "verified" even though `pg_restore` had reported errors. | Verification fails on any non-benign restore error. |
| E5 | `rollback/025_down.sql` as first written would have broken new-organisation creation (dropped a function the trigger still called). | Restores 023's trigger function first; tested. |

## Found by making the test database strict
The in-memory PostgREST stand-in now parses column types, enums, NOT NULL and defaults from the migrations. That surfaced: an invalid `playbooks.category` in a test fixture, and a query selecting
`rule_overrides.id` (the table has no `id`; on PostgREST this is a 400) in the onboarding service.

## Found by the validation lab (see VALIDATION.md)
Event flattening stopped at depth 6 so CloudTrail CIDRs were invisible; quoted executable paths and `cmd ^` escapes defeated every command rule; web-injection rules fired on process command lines; the CloudTrail adapter discarded
Root-user read calls; vendor full image paths broke `process_name` rules; `tar czf` and several GTFOBins/LOLBin/registry/cloud-CLI forms were missed; DB dumps to backup volumes and firewall *denies* were false positives; there was no
stateful failure-burst detection; a Jenkins agent triggered the web-server-shell rule. All fixed with tests; first-run (unfitted) results are recorded in `validation/reports/history.md`.

## Found by building features
| # | Finding | Fix |
|---|---|---|
| E6 | Correlation depended on processing order: events handled concurrently by separate workers could each miss the other's detections, or both report. | Persist own detections first, evaluate the entity group symmetrically, exactly-once ledger (migration 026); order-reversal and forced-race tests. |
| E7 | `TB-COR-007` counted every tactic of a multi-tactic technique, so one event could look like several attack phases. | One (primary) tactic per detection. |
| E8 | Detection throughput was dominated by interpreter overhead (per-evaluation operator lookup, regex cache hits). | Rules compile once into closures (+58% events/s); a differential test proves identical results to the reference interpreter on the whole corpus. |

## Found by the adversarial security suite (SECURITY.md)
| # | Finding | Fix |
|---|---|---|
| E9 | A JSON `NaN`/`Infinity` anywhere in an ingest body produced a **500** (the 422 echo could not be encoded). NUL bytes and lone UTF-16 surrogates would be rejected by PostgreSQL after acceptance. | Sanitised at the model boundary; 422s no longer echo input; DB data-exception errors map to 400. |
| E10 | An invalid `severity`/`actor_type`/run `status` filter reached an enum column and returned a 500. | Typed (`Literal`) query parameters. |
| E11 | An admin could set the organisation's `plan` and `status` through `PATCH /organizations/me`. | Removed from the schema; unknown fields are a 422. |
| E12 | API keys could call `GET /me`, contradicting the "keys reach only scoped endpoints" invariant. | Humans only. |
| E13 | Cross-tenant `GET /rules/{id}/versions` answered 200 with an empty list instead of 404. | 404 when the rule is not in the caller's organisation. |
| E14 | Pinned dependencies carried known advisories (PyJWT 22, cryptography 10, starlette 7, python-multipart 12, orjson 2, python-dotenv 2, requests 2; frontend: vite, zod, launch-editor, vitest tooling). | Upgraded; `pip-audit` on the installed tree and `npm audit --omit=dev` report 0 (3 low remain in the dev-only shadcn scaffolding CLI). |
| E15 | A mid-session change made request-metrics labels depend on Starlette internals (`route.path` is relative on newer versions). | Labels derived from the request path and its matched parameters. |

## Capabilities added in this phase
Durable queue + workers (leases, retries, dead-letter, backpressure, idempotent event store) · retention · 101-rule ATT&CK-mapped corpus with inline tests · 14 correlations (sequence/threshold/rate) · per-tenant rule overrides, custom rules, versions/rollback, Sigma import,
coverage view · Detection Engineering agent with verified tuning proposals · LLM provider abstraction + graceful no-LLM mode · JWKS/OIDC verification · signed, replay-protected ingestion · key rotation and usage tracking · member lifecycle with escalation guards ·
readiness/metrics/doctor/system status · ordered migration runner with rollback, backup, verify and atomic restore · onboarding checklist and demo campaign · validation lab (benchmark, gates, safety model) · performance benchmark · Detection and Operations consoles ·
vitest and Playwright suites · split production compose.

## Not done / residual risk (enterprise phase)
* **Not exercised here:** a live Supabase project, a live LLM, Docker image builds / the production compose stack (no daemon), `tb-executor` on a real firewall, hosted IdP / JWKS endpoints, production-scale performance.
* Tenancy remains enforced in application code (service-role connection); RLS is defence in depth only.
* No SAML/SCIM, no UEBA/statistical baselines (one benchmark gap is exactly that), reconnaissance has no validation scenarios, the ATT&CK catalogue is a curated subset.
* The validation corpus was written by the rule authors; its scores overstate real-world detection (first-run held-out results: 66-73% recall, 4-7% false positives before remediation).
* Per-process rate limiting; Python `re` has no timeout, so ReDoS protection is a load-time heuristic plus input caps.
* No independent security assessment or compliance certification of any kind.
