# 🛡️ ThreatBrain

**An agentic Security Operations Center: deterministic detection + specialist AI agents + human-approved response, with an evidence trail for every decision.**

ThreatBrain ingests security telemetry (host logs, SIEM alerts, cloud audit events), detects attacks with MITRE ATT&CK-mapped rules, lets specialist LLM agents triage, enrich, investigate and plan a response, and then **stops at a human**: nothing is executed on a host until an administrator approves it, and every step lands in an append-only audit trail.

> 🌐 Live demo: [threat-brain.vercel.app](https://threat-brain.vercel.app) · create a workspace at `/signup`, then click **Trigger pipeline** on the dashboard.

---

## What it does

| Capability | How it works |
|---|---|
| **Durable ingestion** | Collectors, SIEM webhooks and the API write events to an idempotent event store and a PostgreSQL job queue, then answer `202`. Workers (scale-out safe: `SKIP LOCKED`, leases, retries, dead-letter) detect, correlate and run the agents. Above a queue ceiling the API answers `503 + Retry-After` instead of accepting unbounded work. |
| **Detection engine** | 101 ATT&CK-mapped rules ([`rules.yaml`](backend/app/detection/rules.yaml)) with inline positive/negative tests, compiled once for speed, ReDoS-guarded. Runs without an LLM, so a model outage degrades the pipeline instead of stopping it. |
| **Correlation** | 14 order-independent, exactly-once correlations: kill-chain sequences (spray -> login, exploit -> shell, dump -> lateral movement, ...), multi-phase thresholds and failure-burst/spraying rates over raw events. |
| **Detection management** | Per-tenant overrides of built-in rules (reason required, audited), custom rules that cannot be enabled until their tests pass, versions with rollback, Sigma import (unsupported constructs refused, not guessed), ATT&CK coverage view. |
| **Agents** | Triage · Threat Intel · Investigation · Response · Forensics · Compliance · Hunt · Log Analysis · **Detection Engineering** (proposes rule tunings from analyst false-positive feedback; the server verifies every proposal against real samples and stores only a draft). Strict schemas, bounded retries, recorded runs with version metadata. Groq or any OpenAI-compatible endpoint, or none. |
| **Evidence-based verdicts** | Rule hits put a *floor* under severity; threat-intel reputation comes from the feeds; log-analysis findings are *verified* only if the cited lines exist. |
| **Safe response** | The Response agent **recommends**; targets must appear in the incident's own evidence; every action waits for an administrator; `tb-executor` carries out *approved* actions behind guards (dry-run by default). The server never executes anything. |
| **Case management & metrics** | Status lifecycle, owner/priority, notes, one chronological timeline, Markdown report, SOC metrics (detection latency, time to case/contain/resolve, noise suppressed, top techniques, agent health). |
| **Identity & tenancy** | Multi-tenant isolation (sweep-tested), RBAC with escalation guards, member lifecycle, Supabase JWT (HS256 or JWKS) and optional OIDC, scoped API keys with rotation, optional HMAC signing + replay protection, append-only audit trail. |
| **Operations** | Readiness/liveness probes, Prometheus metrics, `python -m app.doctor`, Operations console, ordered checksummed migrations with rollback, backup/verify/atomic restore, retention, onboarding checklist and a synthetic demo campaign. |
| **Validation lab** | A reproducible benchmark (attack/benign/campaign/evasion scenarios, held-out rounds, gates) that measures what is detected, what is wrong and what is missed - with the first-run numbers published. |
| **Integrations** | Wazuh, Elastic ECS, CEF/syslog, AWS CloudTrail, Splunk and generic JSON webhooks (adapter-tested against synthetic payloads, **not against live products**); the `tb-collector` host agent; Discord alerts. |

## Architecture

```mermaid
flowchart LR
  subgraph Sources
    COL[tb-collector<br/>host logs] -->|API key / signed| ING
    SIEM[Wazuh · ECS · CEF · CloudTrail · Splunk] -->|webhook| ING
    UI[Console / API] --> ING
  end
  ING[/Ingest API<br/>validate · normalise · idempotent store/] --> Q[(Job queue<br/>PostgreSQL)]
  Q --> W1[Worker] & W2[Worker] & WN[Worker …]
  subgraph WorkerPipeline["Worker (at-least-once, idempotent)"]
    W1 --> DET[Rules + tenant overrides] --> COR[Correlation<br/>exactly-once ledger]
    COR --> TRI{Flagged?}
    TRI -- yes --> AG[Agents: triage · intel · investigate]
    AG --> RESP[Response] & FOR[Forensics] & COMP[Compliance]
  end
  RESP --> AP[(Approval queue)]
  AP -->|human approves| EXE[tb-executor on host]
  WorkerPipeline --> DB[(Supabase Postgres<br/>RLS · append-only audit)]
  DB --> CON[Console<br/>Threats · Detection · Operations]
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · security model: [docs/SECURITY.md](docs/SECURITY.md) · detection content: [docs/DETECTION.md](docs/DETECTION.md) · running it: [docs/OPERATIONS.md](docs/OPERATIONS.md) ·
measured detection quality: [docs/VALIDATION.md](docs/VALIDATION.md) · release gates: [docs/RELEASE.md](docs/RELEASE.md) · what was found and fixed: [docs/AUDIT.md](docs/AUDIT.md).

## Quick start

**Prerequisites:** Python 3.11+, Node 20+, a [Supabase](https://supabase.com) project (free tier is fine), and optionally a [Groq](https://console.groq.com) API key (without it the detection engine, de-dup and correlation still work; the LLM agents report "unavailable").

```bash
# 1. Database: apply the migrations with the ordered, checksummed runner (direct Postgres connection string):
#      DATABASE_URL=postgresql://postgres:...@db.<ref>.supabase.co:5432/postgres ./database/migrate.sh
#    (or paste database/migrations/*.sql IN ORDER into the SQL editor, running 022 and 024 each on their own)
#    Optional sample rows: database/seeders/001_demo_data.sql   -- or load the demo campaign from the console after sign-in

# 2. Configuration
cp .env.example .env && cp .env.example backend/.env     # fill in Supabase + Groq values

# 3. Backend  -> http://localhost:8000/docs
cd backend && python -m venv venv && ./venv/bin/pip install -r requirements-dev.txt
./venv/bin/uvicorn app.main:app --reload --port 8000

# 4. Frontend -> http://localhost:5173   (reads frontend/.env.local)
cd frontend && npm ci && npm run dev
```

Or with Docker: `cp .env.example .env && docker compose up --build` (console on :5173, API on :8000). Production-shaped (API and workers separate, hardened containers, migration job): `docker-compose.prod.yml`, see [docs/OPERATIONS.md](docs/OPERATIONS.md). Then run `python -m app.doctor`.

`frontend/.env.local`:

```
VITE_API_BASE_URL=http://localhost:8000/api/v1
VITE_SUPABASE_URL=https://your-project-ref.supabase.co
VITE_SUPABASE_ANON_KEY=your_anon_key
```

### Connect real telemetry

1. In the console open **Settings → API keys** and create a key (`ingest` for collectors/SIEMs, `executor` for the response executor).
2. Host logs: `cd collector`, copy `collector.example.yaml` → `collector.yaml`, set `api_key` + `log_path`, run `python -m tb_collector --config collector.yaml` ([collector/README.md](collector/README.md)).
3. SIEM: `POST /api/v1/ingest/webhook/{wazuh|ecs|cef|cloudtrail|splunk|generic}` with `X-API-Key`.
4. Response: run `tb_executor` (starts in **dry-run**) and approve actions under **Approvals**.

## Configuration

Everything is environment-driven; [.env.example](.env.example) documents each variable. The important ones:

| Variable | Purpose |
|---|---|
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_SECRET` | Database + auth (required). The JWT secret is the project's legacy HS256 secret. |
| `GROQ_API_KEY` | LLM agents. Per-agent model/temperature/token limits live in the `agents` table. |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` | Threat intel feeds (each optional). |
| `DISCORD_WEBHOOK_URL` | Alerts for new high/critical incidents (only `discord.com` URLs accepted). |
| `APP_ENV=production` | Hides `/docs`, adds HSTS, and refuses to boot with `APP_DEBUG=true`, `CORS_ORIGINS=*` or a weak JWT secret. |
| `ALLOW_PUBLIC_SIGNUP`, `SEED_DEMO_DATA` | Turn both **off** for a real deployment (sample data is tagged `sample-data`). |
| `TRUST_PROXY_HEADERS` | Enable only behind a proxy that overwrites `X-Forwarded-For` (rate limits key on client IP). |
| `DEDUP_WINDOW_MINUTES`, `PIPELINE_STAGE_TIMEOUT_SECONDS`, `LLM_*`, `RATE_LIMIT_*` | Pipeline/LLM tuning and rate limits. |
| `HUNT_INTERVAL_MINUTES` | `>0` runs the Hunt agent for every active org on that schedule (off by default; costs tokens). |
| `EMBEDDED_WORKER`, `WORKER_CONCURRENCY`, `QUEUE_MAX_DEPTH*`, `INGEST_TRIAGE_MODE` | Queue workers and backpressure; `matched` (default) spends tokens only on events a rule or correlation flagged. |
| `LLM_PROVIDER` (`groq`/`openai_compatible`/`none`), `LLM_BASE_URL`, `LLM_MODEL_OVERRIDE` | Model provider; `none` = detection and correlation only. |
| `APP_SECRET`, `METRICS_TOKEN`, `MAX_TOKEN_AGE_MINUTES`, `OIDC_*`, `SUPABASE_JWKS_URL` | Signed ingestion keys, Prometheus, token policy, external IdP, asymmetric JWT keys. |
| `RETENTION_*_DAYS`, `ALLOW_DEMO_LOAD` | Data retention; demo campaign. Full list with comments: [.env.example](.env.example). |

## API overview

Interactive docs at `/docs` (disabled in production). Highlights: `POST /ingest/event` (`?async=true` for the durable path), `POST /ingest/events`, `POST /ingest/webhook/{format}`, `GET|POST|PUT|DELETE /rules…` (overrides, custom rules, Sigma, coverage, tuning proposals), `GET /onboarding`, `GET /system/status`, `GET /ready`, `GET /metrics`, `POST /orchestrator/handle-event`, `GET /orchestrator/runs[/{id}]` (execution traces), `GET|PATCH /incidents`, `…/{id}/notes`, `…/{id}/timeline`, `…/{id}/report`, `GET|PATCH /threats`, `GET /playbooks/approvals`, `POST …/{id}/decision`, `POST …/{id}/execution`, `POST /agents/log-analysis/analyze`, `GET /stats/soc`, `GET|POST|DELETE /api-keys`, `POST /copilot/ask`, `GET /audit`.

Errors are JSON (`{"detail": {"error": "...", "message": "..."}}`); 401 unauthenticated, 403 role/scope/no organization, 404 across tenants, 409 conflicts (already-decided approvals), 429 rate-limited (`Retry-After`), 502 when the model is unavailable.

## Testing

```bash
cd backend   && pip install -r requirements-dev.txt && ruff check app tests validation bench && pytest -q      # 656 tests
cd backend   && python -m validation.runner --mode engine --gate && python -m validation.runner --mode pipeline --gate   # detection quality gates
cd collector && pip install -r requirements-dev.txt && pytest -q                                                # 127 tests
cd frontend  && npm ci && npm run lint && npx tsc -b && npm test && npm run build                               # 18 component tests
cd frontend  && npm run e2e            # Chromium against the real backend app + production bundle (needs Playwright; 19 checks)
PGHOST=... PGUSER=... ./database/verify_migrations.sh && ./database/tests/test_queue.sh && ./database/tests/test_security.sh && ./database/tests/test_ops.sh   # real PostgreSQL
python3 scripts/release_gates.py --db --e2e   # runs every gate that can run here and writes docs/reports/release-report.{json,md}
```

The backend suite needs no credentials: it runs the real FastAPI app against a **schema-aware in-memory PostgREST stand-in** (columns, enums, NOT NULL and defaults are parsed from `database/migrations`, so a query on a non-existent column
or an invalid enum value fails like production would) and a scripted LLM. It covers authentication (forged/expired/`alg=none`/algorithm-confusion tokens, JWKS and OIDC with locally generated keys), the role matrix, route-by-route auth and
**cross-tenant sweeps generated from the OpenAPI document**, the queue/worker semantics, the full pipeline (de-duplication, degraded mode, prompt-injection containment, approval flow), SIEM adapters, every rule's inline tests, correlation order-independence,
signing/replay/rotation, member lifecycle, parser abuse, and the validation benchmark. `backend/tests/e2e_server.py` boots the same app on that stand-in for browser testing.

## Repository layout

```
backend/    FastAPI app: agents/, detection/ (rules, correlations, engine, Sigma, ATT&CK catalogue), ingest/ (SIEM adapters + normalisation),
            integrations/ (feeds), services/ (queue, worker, event processor, orchestrator, rules, ops, case mgmt, API keys),
            api/v1/endpoints/, tests/, validation/ (benchmark lab), bench/ (performance)
collector/  tb_collector (log tailing + detections), tb_executor (approved actions), tb_common (API session)
frontend/   React 19 + Vite + Tailwind v4 console
database/   migrations/ (001-026), rollback/, seeders/, migrate.sh, backup.sh, restore.sh, tests/ (real-PostgreSQL), verify_migrations.sh
scripts/    release_gates.py (runs every gate, writes the machine-readable report)
docs/       ARCHITECTURE, SECURITY, DETECTION, VALIDATION, OPERATIONS, RELEASE, AUDIT, reports/
```

## Verification status (be aware)

**Run and passed in the build environment** (details and exact numbers: [docs/reports/release-report.md](docs/reports/release-report.md), regenerate with `scripts/release_gates.py`):
backend 656 tests on Python 3.11 and 3.13 · detection benchmark gates in engine and pipeline mode (169/169 attacks, 0/125 benign false positives on the tuned corpus - **first-run held-out results were 66-73% recall and 4-7% false positives**, see [VALIDATION.md](docs/VALIDATION.md)) ·
collector 127 tests · frontend lint (0 errors), type-check, 18 component tests, production build · 19 Chromium checks against the real app and bundle · on **PostgreSQL 16**: all 26 migrations, the queue under concurrency, RLS/tenant isolation/append-only audit,
migration runner (drift refusal, concurrent runners, baseline), rollback, backup/verify/atomic restore · `pip-audit` (installed tree) and `npm audit --omit=dev` at 0 known vulnerabilities · `bandit` medium+ clean · `docker compose config` for both compose files.

**Not exercised** (no credentials/daemon in the build environment, so treat as unverified): a live Supabase project (PostgREST, GoTrue, Realtime), live Groq/AbuseIPDB/VirusTotal/OTX/Discord calls (HTTP layers and the OpenAI-compatible client are tested against local stubs), a live OIDC/JWKS endpoint (locally generated keys only),
**Docker image builds and running the compose stacks**, `tb-executor` against a real firewall, any SIEM product (adapters are tested with synthetic payloads), and performance on production infrastructure. Apply migrations through 026 and do a staging deployment before relying on it ([docs/OPERATIONS.md](docs/OPERATIONS.md)).

## Known limitations

* **No certification or independent assessment.** ThreatBrain is not SOC 2 / ISO 27001 certified or assessed; see [docs/SECURITY.md](docs/SECURITY.md) for the controls and their gaps.
* The backend reaches the database with the service-role key and enforces tenancy in code (every query is filtered by `organization_id`; covered by route sweeps); RLS is defence in depth. A missed filter would be a data leak.
* **Detection quality numbers are optimistic**: the benchmark was written by the rule authors. Seven evasion probes in twelve are still missed and one realistic behaviour (secret read by an unfamiliar principal) needs a baseline, which does not exist. No UEBA/statistical detection, no SAML/SCIM.
* LLM output is non-deterministic. Mitigations are schema validation, bounded retries, rule reconciliation, server-side target validation and human approval, not guarantees. LLM verdict quality is not measured by any gate.
* API rate limits are per process. `re` has no timeout: rule safety is a load-time heuristic plus input caps.
* The demo seed data and the `203.0.113.x` / `198.51.100.x` sample addresses are fixtures; set `SEED_DEMO_DATA=false` and `ALLOW_DEMO_LOAD=false` for real use.

## License

MIT, see [LICENSE](./LICENSE). Built by [Vansh Mahajan](https://github.com/Vansh150705).
