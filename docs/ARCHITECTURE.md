# Architecture

## Components

| Component | Tech | Responsibility |
|---|---|---|
| Console | React 19, Vite, Tailwind v4 | Dashboards, cases, approvals, settings. Talks to the API with the Supabase user JWT; reads new threats live through Supabase Realtime. |
| API | FastAPI (sync endpoints run in the thread pool) | Auth, RBAC, ingest, orchestration, case management, metrics. Single place that touches the database. |
| Detection layer | Pure Python + YAML | Rules, IOC extraction, fingerprints, risk score. No network, no LLM. |
| Agents | Groq (JSON mode) | Eight narrowly-scoped prompts with Pydantic output schemas. |
| Database | Supabase Postgres | Tenant data, append-only `audit_logs`, `pipeline_runs`, `api_keys`. |
| `tb-collector` | Python daemon | Tails logs, detects attacks, posts events (API key, retry, disk spool). |
| `tb-executor` | Python daemon | Polls for **approved** actions, guards them, executes, reports back. |

## Pipeline

`backend/app/services/orchestrator_service.py`

1. **Detection** – evaluate rules, extract IOCs, compute a fingerprint. Always runs.
2. **De-duplication** – an active threat with the same fingerprint inside `DEDUP_WINDOW_MINUTES` absorbs the event (`event_count`, `last_seen_at`); the remaining stages are skipped and no tokens are spent.
3. **Triage (LLM)** – classifies, maps ATT&CK, cites evidence. Prompt receives the rule hits as shared context.
   *LLM unavailable?* If rules matched, a clearly-marked **degraded** verdict is built from them; otherwise the stage fails and the pipeline stops cleanly.
4. **Reconcile** – a rule match with confidence ≥ 70 puts a floor under severity; rule MITRE IDs/tags/evidence are merged; medium+ rule-corroborated events are always promoted. Every adjustment is recorded on the threat (`ai_analysis.reconciliation`).
5. **Promote** – threat row with fingerprint, rule hits, risk score (transparent breakdown in `risk.py`).
6. **Threat intel** – all configured feeds → composite score; folded back into the threat (`enrichment`, risk re-scored, `known-malicious-source` tag).
7. **Correlate / investigate** – (a) join an active incident that already involves the attacker IP (deterministic); else (b) the Investigation agent groups *unlinked* recent threats; else (c) a lone high/critical threat becomes its own incident.
8. **Response ∥ Forensics ∥ Compliance** – independent, run concurrently. Forensics writes the timeline onto the incident; Response writes `playbook_runs`; Compliance writes its summary into `ai_summary`.

Each stage is timed and bounded (`PIPELINE_STAGE_TIMEOUT_SECONDS`), retried only for schema-invalid model output, and recorded in `trace`. Full runs are persisted in `pipeline_runs` (sync, or background with `?async=true` / webhooks) and visible under **Pipelines** in the console.

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

* Human callers: Supabase JWT (HS256, audience `authenticated`, `exp`/`sub`/`iat` required); the profile row supplies `organization_id` and role.
* Machine callers: `X-API-Key` (`tbk_…`, SHA-256 stored, scopes `ingest`/`executor`, role `analyst`, optional expiry, revocable). A key is rejected everywhere except endpoints that declare its scope.
* The API uses the service-role connection, so **every query is filtered by `organization_id`** (see `services/*` and the `test_auth_rbac` isolation tests). Users without an organization get 403 on all tenant endpoints.
* Roles: viewer < analyst < admin < owner. Analysts triage and run agents; admins decide approvals and manage keys.

## Data model additions (migrations 022–023)

`threats(fingerprint, event_count, last_seen_at, rule_hits)`, `incident_notes`, `api_keys`, `pipeline_runs`, the `log_analysis` agent (enum value + per-org seed + trigger). RLS is enabled on the new tables with no policies, so only the backend can read them (key hashes in particular).

## Extending

* **Add a detection rule**: append to `detection/rules.yaml` (operators documented in its header) and add a case to `tests/test_detection.py`; `test_adversarial_inputs…` guards against regexes with super-linear backtracking (use bounded `.{0,200}`).
* **Add a SIEM format**: write an adapter in `ingest/adapters.py` returning `TriageInput`s and register it in `_ADAPTERS`.
* **Add an agent**: subclass `BaseAgent`, add the enum value + seed (see 022/023), and call it from the orchestrator or an endpoint.
