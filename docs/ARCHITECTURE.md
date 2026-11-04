# Architecture

## Components

| Component | Tech | Responsibility |
|---|---|---|
| Console | React 19, Vite, Tailwind v4 | Dashboards, cases, approvals, **detection management, operations, onboarding**, settings. Talks to the API with the Supabase user JWT; reads new threats live through Supabase Realtime. |
| API | FastAPI (sync endpoints run in the thread pool) | Auth, RBAC, **durable ingest**, orchestration, case management, rule management, metrics, readiness. Single place that touches the database. |
| Worker | Python (`python -m app.worker`, or embedded) | Claims jobs from the PostgreSQL queue (`FOR UPDATE SKIP LOCKED`, leases, retries, dead-letter), runs detection, correlation and the agent pipeline. Scale by running more. |
| Detection layer | Pure Python + YAML | 126 compiled rules, 17 correlations, a deobfuscation layer, ATT&CK catalogue, Sigma converter, IOC extraction, fingerprints, risk score. No network, no LLM. |
| Agents | Groq or any OpenAI-compatible endpoint (JSON mode) | Nine narrowly-scoped prompts with Pydantic output schemas (incl. Detection Engineering). Optional: with no model the platform runs rules-only. |
| Database | Supabase Postgres | Tenant data, event store, **job queue**, append-only `audit_logs`, `pipeline_runs`, `api_keys`, rule content, correlation ledger. |
| `tb-collector` | Python daemon | Tails logs, detects attacks, posts events (API key, retry, disk spool). |
| `tb-executor` | Python daemon | Polls for **approved** actions, guards them, executes, reports back. |

## Ingestion path (durable, asynchronous)

`POST /ingest/event?async=true`, `/ingest/events` and `/ingest/webhook/{format}` do three things and return **202**: validate/normalise, store the event idempotently
(unique `(organization_id, idempotency_key)`; a re-delivery is reported as a duplicate), and enqueue an `event.process` job. A queue ceiling answers **503 + Retry-After** instead of accepting unbounded work.
The worker (`services/event_processor.py`) then: (1) evaluates the tenant's rules (built-in + overrides + custom), (2) **persists that event's detections**, (3) evaluates correlations over the entity's recent events -
symmetric and exactly-once via the `correlation_hits` ledger, so concurrent workers neither miss nor double-report a completed pattern - and (4) if anything fired (`INGEST_TRIAGE_MODE=matched`) runs the agent pipeline below,
linking the event(s) to the resulting threat (`threat_events`). Jobs are at-least-once: handlers are idempotent; a worker that dies loses its lease and the job is reclaimed; exhausted jobs are dead-lettered and can be requeued by an admin.
The synchronous `POST /ingest/event` (no `async`) and `/orchestrator/handle-event` still run the whole pipeline inline for tests and manual use.

## Pipeline

`backend/app/services/orchestrator_service.py`

1. **Detection** – evaluate the tenant's rules (plus any correlation hits handed in by the event processor), extract IOCs, compute a fingerprint. Always runs.
2. **De-duplication** – an active threat with the same fingerprint inside `DEDUP_WINDOW_MINUTES` absorbs the event (`event_count`, `last_seen_at`); the remaining stages are skipped and no tokens are spent.
3. **Triage (LLM)** – classifies, maps ATT&CK, cites evidence. Prompt receives the rule hits as shared context.
   *LLM unavailable?* If rules matched, a clearly-marked **degraded** verdict is built from them; otherwise the stage fails and the pipeline stops cleanly.
4. **Reconcile** – a rule match with confidence ≥ 70 puts a floor under severity; rule MITRE IDs/tags/evidence are merged; medium+ rule-corroborated events are always promoted. Every adjustment is recorded on the threat (`ai_analysis.reconciliation`).
5. **Promote** – threat row with fingerprint, rule hits, risk score (transparent breakdown in `risk.py`).
6. **Threat intel** – all configured feeds → composite score; folded back into the threat (`enrichment`, risk re-scored, `known-malicious-source` tag).
7. **Correlate / investigate** – (a) join an active incident that already involves the attacker IP (deterministic); else (b) the Investigation agent groups *unlinked* recent threats; else (c) a lone high/critical threat becomes its own incident.
8. **Response ∥ Forensics ∥ Compliance** – independent, run concurrently. Forensics writes the timeline onto the incident; Response writes `playbook_runs`; Compliance writes its summary into `ai_summary`.

Each stage is timed and bounded (`PIPELINE_STAGE_TIMEOUT_SECONDS`), retried only for schema-invalid model output, and recorded in `trace`. Full runs are persisted in `pipeline_runs` (sync, or background with `?async=true` / webhooks) and visible under **Pipelines** in the console.

## Behavioural layer

After deterministic rules run, `event_processor` passes the event to `behavior_service`, which extracts observations (sign-in network/hour/host, privileged actions, processes, destinations, bytes), compares them with the entity's tenant-specific baseline and peer group,
and returns zero or more hits that are merged with the rule hits (`TB-UEBA-*`). Only events with no deterministic hit update baselines. Profiles are stored in `behavior_profiles` with optimistic concurrency; analyst dispositions and suppressions are stored beside them.
Details and limits: [BEHAVIORAL_ANALYTICS.md](BEHAVIORAL_ANALYTICS.md).

## Response safety model

```
LLM proposes ──► server validates ──► approval queue ──► human approves ──► tb-executor guards ──► host
 (untrusted)      · action allow-list   (status=pending)   (admin/owner)      · IP/CIDR/user rules
                  · target ∈ incident                                          · enabled_actions
                    evidence                                                   · dry_run default
                  · playbook enabled + min_confidence                          · audit trail entry
                  · no duplicate pending/approved
```

* The server **never executes** an action; `executed` only appears after `tb-executor` reports it.
* `dry_run`/`simulate` records what would be proposed and queues nothing.
* Approvals are decided with a conditional update (`WHERE status='pending'`) so two admins cannot both win; reporting execution is likewise single-shot.

## Prompt-injection posture

Everything from the outside world (usernames, URLs, command lines, log lines, threat-feed comments, even threat titles shown to the copilot) is untrusted. Defences, in order of strength:

1. **Server-side validation of consequences** (above): the model cannot choose an arbitrary firewall target.
2. **Structured outputs**: Pydantic schemas, enumerations, ATT&CK-ID regex, bounded lists.
3. **Evidence verification**: log-analysis line numbers and entities are checked against the submitted text; reputations come from feeds.
4. **Fencing**: the data half of every prompt is wrapped in `<untrusted_data>` (fence-forging text is stripped) and the system prompt says fenced content is never instructions.
5. **Human approval** for every state-changing action.

(4) is a mitigation, not a guarantee; (1), (3) and (5) are what make a successful injection unprofitable.

## Tenancy and authentication

* Human callers: Supabase JWT (HS256 against the project secret, or ES256/RS256 via JWKS; audience `authenticated`, `exp`/`sub`/`iat` required, optional max token age); optionally an external OIDC IdP, mapped to an already provisioned user by verified email.
  The profile row supplies `organization_id`, role and status on **every** request.
* Machine callers: `X-API-Key` (`tbk_…`, SHA-256 stored, scopes `ingest`/`executor`, role `analyst`, optional expiry, revocable, rotatable, usage-tracked, optionally HMAC-signed with replay protection). A key is rejected everywhere except endpoints that declare its scope.
* Full model, tests and gaps: [SECURITY.md](SECURITY.md).
* The API uses the service-role connection, so **every query is filtered by `organization_id`** (see `services/*` and the `test_auth_rbac` isolation tests). Users without an organization get 403 on all tenant endpoints.
* Roles: viewer < analyst < admin < owner. Analysts triage and run agents; admins decide approvals and manage keys.

## Data model additions

* 022-023: `threats(fingerprint, event_count, last_seen_at, rule_hits)`, `incident_notes`, `api_keys`, `pipeline_runs`, the `log_analysis` agent.
* 024-025: the `detection_engineering` agent; event-store columns on `events` (idempotency key, detections, ATT&CK ids), `threat_events` (evidence chain), `jobs` + `claim_jobs()` (queue), `worker_heartbeats`,
  `detection_rules` / `detection_rule_versions` / `rule_overrides`, `replay_guard`, API-key hardening columns, `schema_migrations`, `purge_expired()`; a fix for the IOC upsert index.
* 026: `correlation_hits` (exactly-once correlation ledger).
RLS is enabled on **every** table; tables with secrets or internal state have no policy at all, so only the backend can read them.

## Extending

* **Add a detection rule**: append to `detection/rules.yaml` with inline `tests` (a positive and a negative; CI runs them), add a scenario to `backend/validation/scenarios/`, and run `python -m validation.runner --gate` (see [DETECTION.md](DETECTION.md), [VALIDATION.md](VALIDATION.md)). Unbounded regex wildcards and nested quantifiers are rejected at load time.
* **Add a correlation**: `detection/correlations.yaml` (kind `sequence` / `threshold` / `rate`) with inline scenarios; they are evaluated in both processing orders.
* **Add a job type**: register a handler with `@register("kind")` in `services/worker.py`; make it idempotent (delivery is at-least-once) and raise `PermanentJobError` for payloads that can never succeed.
* **Add an LLM provider**: implement the small `.chat.completions.create(**kw)` surface (see `_CompatClient` in `services/llm_service.py`) and a `LLM_PROVIDER` value.
* **Add a SIEM format**: write an adapter in `ingest/adapters.py` returning `TriageInput`s and register it in `_ADAPTERS`.
* **Add an agent**: subclass `BaseAgent`, add the enum value + seed (see 022/023), and call it from the orchestrator or an endpoint.
