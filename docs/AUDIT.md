# Audit report

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

## Not done / residual risk
* Live Supabase, Groq, feed and Discord calls, Docker image builds and the executor on a real firewall were **not exercised** in the build environment (see README → Verification status).
* HS256-only JWT verification (asymmetric Supabase signing keys need a JWKS verifier).
* In-memory rate limiter and background pool (single-process design; documented).
* No automated frontend tests (the console was checked with a scripted Chromium pass; 40 pre-existing-style `react-hooks`/`react-refresh` lint *warnings* remain, 0 errors).
* The rule set is deliberately small; detection coverage is a continuing programme, not a finished one.
* `backend/scripts/test_*.py` are legacy live-API smoke scripts (they hit a deployed backend); they are not part of the test suite.
