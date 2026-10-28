# Operations guide

How to deploy, run, upgrade, back up and troubleshoot ThreatBrain. Everything here was exercised in a test environment unless marked
**[not exercised]**; see "What has and has not been verified" at the end and [RELEASE.md](RELEASE.md).

## 1. Topologies

| Mode | When | How |
|---|---|---|
| **Single container** | Evaluation, small teams | One API container; `EMBEDDED_WORKER=true` runs a queue worker thread inside it. `docker compose up --build` |
| **Split** (recommended) | Anything real | `docker-compose.prod.yml`: `api` (stateless), `worker` (N replicas, `python -m app.worker`), `frontend` (nginx static), one-shot `migrate` job. API and workers scale independently. |

State lives in PostgreSQL only (Supabase). The API and workers are stateless and can be restarted at any time: an event that was accepted
is in the database and in the queue, so it survives a restart (at-least-once delivery, idempotent handlers).

```
collector / SIEM -> POST /ingest/* -> events table + jobs table (202, durable) -> worker(s) -> detect -> correlate -> [agent pipeline] -> threats / incidents / approvals
```

## 2. First deployment

```bash
cp .env.example .env                     # fill in Supabase + secrets; set APP_ENV=production
# 1. schema (direct Postgres connection string, NOT the pooled/REST URL)
DATABASE_URL=postgresql://postgres:...@db.<ref>.supabase.co:5432/postgres ./database/migrate.sh --dry-run
DATABASE_URL=... ./database/migrate.sh
# 2. start
docker compose -f docker-compose.prod.yml up -d --build        # [not exercised: no Docker daemon in the build environment]
# 3. verify
docker compose -f docker-compose.prod.yml exec api python -m app.doctor
curl -fsS http://127.0.0.1:8000/api/v1/ready
```

`python -m app.doctor` checks configuration (and prints every invalid production setting at once, with the fix), database reachability,
schema level, workers and queue. It exits non-zero on any `FAIL`.

Databases that were set up by hand in the Supabase SQL editor: record what is already applied, then migrate forward:
`./database/migrate.sh --baseline 023` (records 001-023 without running them), then `./database/migrate.sh`.

### Production configuration that matters

`APP_ENV=production` refuses to start with `APP_DEBUG=true`, `CORS_ORIGINS=*`, a short JWT secret or a malformed OIDC/`APP_SECRET`.
Beyond that, set: `ALLOW_PUBLIC_SIGNUP=false`, `SEED_DEMO_DATA=false`, `ALLOW_DEMO_LOAD=false`, `TRUST_PROXY_HEADERS=true` *only* behind a proxy
that overwrites `X-Forwarded-For`, `APP_SECRET` (enables signed ingest keys), `METRICS_TOKEN` (enables `/metrics`), and keep the API on
127.0.0.1 behind a TLS-terminating reverse proxy. The service-role key must never reach the browser.

## 3. Schema migrations: ordering, upgrade, rollback

* Files in `database/migrations/` apply in filename order; `migrate.sh` records each in `public.schema_migrations` with a SHA-256 checksum, runs each in its
  own session and transaction, holds a Postgres advisory lock (two concurrent deploys serialise), and **refuses to continue** if an already-applied file was
  edited (`DRIFT`, exit 3). `--status`, `--dry-run` and `--baseline N` are read-only or bookkeeping-only.
* 022 and 024 add enum values and must be their own transaction: the runner guarantees this; if you paste into the Supabase SQL editor, run them alone.
* All migrations are idempotent (`IF NOT EXISTS` / `OR REPLACE`), so re-running after a failure is safe.
* **Upgrade order:** migrate first, then roll out API/worker images (the API's `/ready` stays `503` until the schema it needs is present, so a deploy in the
  wrong order fails safe).
* **Rollback:** the supported path is *application rollback + restore from backup*. For a quick schema rollback of the newest migrations there are manual,
  destructive scripts: `database/rollback/026_down.sql`, `025_down.sql` (they drop the objects those migrations created; they cannot remove enum
  values added by 022/024). Tested: 025 down restores the previous organisation trigger, new organisations still work, and re-applying works.
* Verified on PostgreSQL 16: fresh install of all migrations, idempotent re-run, drift refusal, two concurrent runners (each file applied once), baseline,
  rollback + re-apply. Run `./database/tests/test_ops.sh` (needs a server and createdb rights). Not verified: a hosted Supabase project (its `postgres` role and extensions differ from the stand-ins used in tests).

## 4. Backup and recovery

```bash
DATABASE_URL=... ./database/backup.sh /backups                    # pg_dump custom format of schema public + sha256
VERIFY_ADMIN_URL=... VERIFY_PREPARE_SQL=... ./database/backup.sh --verify /backups/threatbrain-<ts>.dump   # restore into a scratch DB, compare row counts
DATABASE_URL=... ./database/restore.sh /backups/threatbrain-<ts>.dump --yes       # atomic data restore
```

* **Restore is atomic:** one transaction truncates every public table and loads the dump; any failure rolls back and leaves current data untouched
  (tested: schema mismatch aborts with no change; a tampered dump is refused by its checksum). It needs the privilege to
  `SET session_replication_role = replica` (superuser; on Supabase use the `postgres` role). **[not exercised on a hosted Supabase project]**
* **Not in the dump:** Supabase Auth data (`auth` schema: passwords, MFA, sessions) is owned by Supabase: use its backups/PITR. Restoring `public.users`
  without matching `auth.users` leaves orphan profiles. API keys are stored hashed (the raw keys are unrecoverable by design); signing secrets are
  derived from `APP_SECRET` - back that up in your secret manager.
* **Policy suggestion:** daily dump + Supabase PITR; keep 7 daily and 4 weekly, encrypt at rest, run `--verify` on a schedule and after each schema change, and
  rehearse a full restore into a staging project at least quarterly. RPO is your dump interval (PITR gives finer); RTO is dominated by restore time (measure it).
* After a restore: `./database/migrate.sh --status` (roll an older dump forward), start workers, run `python -m app.doctor`.

## 5. Retention

`maintenance.purge` runs about every 6 hours on one worker (`public.purge_expired`): events not linked to any threat after `RETENTION_EVENTS_DAYS` (30),
events kept as evidence after `RETENTION_EVIDENCE_DAYS` (365), finished jobs after `RETENTION_JOBS_DAYS` (14), pipeline runs after `RETENTION_RUNS_DAYS`
(90), expired replay-guard rows immediately. **`audit_logs` is append-only and never purged** (a database trigger blocks UPDATE/DELETE; tested on PostgreSQL);
archive it with your own process if it grows. Tune the numbers to your legal and storage requirements - they are defaults, not advice.

## 6. Monitoring

* **Probes:** `GET /api/v1/health` (liveness), `GET /api/v1/ready` (503 unless the database answers and the schema is present; queue/worker problems are
  returned as warnings so a stalled worker pool does not remove the API from a load balancer). Admin UI: **Operations** (also `GET /api/v1/system/status`).
* **Prometheus:** `GET /metrics` with `Authorization: Bearer $METRICS_TOKEN` (404 if no token is configured). Per-process counters/histograms plus queue and
  worker gauges computed from the database at scrape time:

| Metric | Meaning |
|---|---|
| `tb_queue_jobs{status}` / `tb_queue_oldest_queued_seconds` | backlog; alert if oldest > 300 s |
| `tb_workers_live` | workers with a heartbeat in the last 60 s; alert if 0 |
| `tb_jobs_finished_total{kind,result}` | `succeeded` / `retried` / `dead`; alert on any `dead` |
| `tb_events_ingested_total{outcome}` | `accepted` / `duplicate` |
| `tb_detection_hits_total{rule,kind}` | per-rule hit rate (find noisy rules, and rules that never fire) |
| `tb_llm_calls_total`, `tb_llm_tokens_total`, `tb_llm_call_duration_seconds` | model health and cost |
| `tb_pipeline_runs_total{outcome}` | `completed` / `degraded` / `failed` |
| `tb_http_requests_total{route,method,status}`, `tb_http_request_duration_seconds` | API RED metrics (route templates, bounded cardinality) |
| `tb_auth_failures_total{reason}` | credential-stuffing / misconfigured collectors |

Example alerts: `tb_workers_live == 0 for 2m`, `tb_queue_oldest_queued_seconds > 300 for 5m`, `increase(tb_jobs_finished_total{result="dead"}[15m]) > 0`,
`rate(tb_http_requests_total{status="5xx"}[5m]) / rate(tb_http_requests_total[5m]) > 0.02`, `increase(tb_auth_failures_total[5m]) > 50`.
Structured JSON logs carry `request_id`, `organization_id` and `user_id`; ship them to your log pipeline.

## 7. Scaling and limits

* **Ingest** is bounded by `QUEUE_MAX_DEPTH` / `QUEUE_MAX_DEPTH_PER_ORG`: above them the API answers **503 with `Retry-After`** instead of accepting unbounded
  work (collectors already retry and spool to disk). `INGEST_MAX_BATCH` (50) and a 1 MB body limit bound each request.
* **Workers:** add replicas (`--scale worker=N`); `claim_jobs` uses `FOR UPDATE SKIP LOCKED` (tested: 8 concurrent claimers, 4000 jobs, each claimed exactly
  once). A worker that dies mid-job loses its lease after `JOB_LEASE_SECONDS` and the job is reclaimed; after `JOB_MAX_ATTEMPTS` it is dead-lettered
  (Operations -> requeue).
* **Cost control:** `INGEST_TRIAGE_MODE=matched` (default) sends only events that a rule or correlation flagged to the LLM pipeline; benign telemetry costs
  no tokens. With the LLM down or `LLM_PROVIDER=none` the platform keeps detecting, correlating and raising threats in a clearly marked *degraded* mode.
* **Measured on a 4-vCPU shared sandbox** (see `backend/bench`, `backend/bench/reports/perf_report.json`; treat as order-of-magnitude, not a capacity promise):
  rule evaluation ~1.2k events/s per core (101 rules, p95 1.6 ms); end-to-end worker processing ~250 events/s per worker process against an in-memory DB
  (excludes LLM and real database latency); `claim_jobs` ~1.8k claims/s on a local PostgreSQL 16 with 8 concurrent claimers. Not measured: LLM throughput,
  hosted-Supabase latency, multi-node scaling. Run the benchmark on *your* infrastructure before sizing.
* In-memory API rate limiting is per process. Behind several API replicas the effective limit multiplies; enforce shared limits at the proxy if that matters.

## 8. Runbooks

| Symptom | Check | Action |
|---|---|---|
| Events accepted but no threats appear | Operations: workers live? queue oldest? | Start workers (`python -m app.worker` / `--scale worker=2`); check `tb_workers_live`. |
| Ingest returns 503 `queue_full` | `tb_queue_jobs`, worker count | Add workers; if a flood, look at `tb_detection_hits_total` for a noisy rule and disable/re-grade it for the tenant. |
| Dead-lettered jobs | Operations -> Dead-lettered jobs (last error) | Fix the cause (usually a bad payload or an outage), then **Requeue**. |
| Every threat says "degraded" | Operations -> language model | Provider outage or missing key: detection still works; fix the provider; `LLM_PROVIDER=none` makes rules-only mode explicit. |
| `/ready` is 503 | `python -m app.doctor` | Database unreachable (check `SUPABASE_URL`/service key) or migrations missing (`./database/migrate.sh`). |
| A rule floods analysts | Detection -> Built-in rules (hit counts via metrics) | Disable or re-grade for your tenant (reason required, audited); or ask the Detection Engineering agent for a verified tuning proposal after marking false positives. |
| API key leaked | Settings -> API keys | Revoke immediately (effect is instant), then rotate collectors to a new key. Prefer signed keys (`require_signature`). |
| User offboarded | Settings -> Team | Disable the member: next request is refused (profile is checked on every call). Also disable them in Supabase Auth. |
| Suspected replay of signed ingest | `tb_auth_failures_total`, 409 `replayed_request` in logs | Expected rejects; investigate sources; rotate the key if a signing secret may be exposed. |
| Restore needed | section 4 | Stop API+workers, `restore.sh --yes`, `migrate.sh`, start, `doctor`. |

## 9. Demo environment and first-run experience

The dashboard shows a **Getting started** checklist computed from real data (LLM configured, ingest key created, first event received, first threat,
executor connected, rules reviewed, team invited). Admins can click *Load a synthetic attack campaign* (`POST /onboarding/demo`): about 12 events
(spray -> login, Log4Shell -> reverse shell, defence evasion -> shadow-copy deletion, cloud privilege grant -> CloudTrail disabled, plus benign noise)
using documentation-range IPs, ingested through the **real pipeline**, so the threats, correlations and incidents you see are genuine pipeline output.
Disable with `ALLOW_DEMO_LOAD=false` in production. The legacy `SEED_DEMO_DATA` sample rows are separate (tagged `sample-data`).

## 10. What has and has not been verified

Verified in the build environment: the backend test suite (656 tests on Python 3.11 and 3.13), the validation benchmark gates, PostgreSQL 16 for the queue
(SKIP LOCKED, leases, dead-letter, retention), RLS/tenant isolation/append-only audit, the migration runner, rollback, backup, verify and restore, the
Chromium browser tests against the real app on an in-memory database, and `docker compose config` for both compose files.
**Not verified:** a live Supabase project, a live LLM, Docker image builds and running the compose stack (no daemon was available), `tb-executor`
against a real firewall, performance on production infrastructure. Do a staging deployment and run `python -m app.doctor`, the Operations page and a
backup `--verify` before trusting a production rollout.
