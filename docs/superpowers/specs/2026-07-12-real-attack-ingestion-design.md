# Real Attack Ingestion for ThreatBrain — Design Spec

**Date:** 2026-07-12
**Status:** Approved (design), pending implementation plan
**Author:** Vansh Mahajan

## 1. Problem

ThreatBrain today can *reason* about a security event but has no way to *receive*
real ones. The pipeline (`POST /api/v1/orchestrator/handle-event`) only runs on
hand-built events posted by the demo's "Trigger pipeline" button. There is no
bridge from real telemetry (logs, IDS alerts, application signals) into the
pipeline, and the Response agent only *recommends* actions — nothing is ever
actually executed.

## 2. Goal & Vision

ThreatBrain should be a **generic attack-monitoring platform** that any website,
web application, or piece of software can plug into to get its real attacks
triaged, investigated, and responded to.

The reusable core we are building is a **universal ingestion boundary** (one
stable "front door" contract) plus **pluggable collectors** that adapt different
systems into that boundary. Kali Linux + SSH brute-force is the **first test
harness**, not the product: the user will attack a Kali box from a Windows/other
machine and confirm the whole chain works end to end.

### Success criteria (first milestone)

A real SSH brute-force launched from an attacker machine against a monitored host
results in:

1. A real **threat** and **incident** appearing in the dashboard, correctly
   triaged (severity, MITRE), enriched (attacker IP via AbuseIPDB), and correlated.
2. A **"Block Malicious IP"** recommendation landing in the `/approvals` queue.
3. On human approval in the web UI, the attacker IP is **really blocked** on the
   monitored host (via `iptables`/`ufw`), and the attack visibly stops.
4. The full chain is visible in the append-only **audit trail**.

## 3. Scope

### In scope
- Universal ingestion endpoint (`POST /api/v1/ingest/event`).
- `tb-collector` daemon with a pluggable source-adapter design; first adapter =
  SSH brute-force from `/var/log/auth.log`.
- `tb-executor` daemon that blocks IPs on approval (poll-based, outbound-only).
- Minimal backend additions: ingest endpoint, executor endpoints, and
  execution-state columns on `playbook_approvals`.
- NOTE: the "Block Malicious IP" playbook is **already seeded** for every org by
  the existing `011_playbooks.sql` trigger (`handle_new_organization` →
  `seed_default_playbooks_for_org`), so no playbook seeding work is required —
  only verification.
- Real end-to-end test using `hydra` against Kali.

### Out of scope (YAGNI — noted for later, not built now)
- Queue / async workers behind the ingest endpoint. Not needed: the collector
  only emits *aggregated notable detections*, so synchronous pipeline-per-event
  is acceptable at lab volume.
- In-app SDK / middleware collector and webhook collector. Designed-for via the
  shared event contract; built later as additional adapters.
- Local LLM / local Postgres (fully-offline stack).
- nmap port-scan adapter — optional milestone 2, same collector interface.
- Dedicated service accounts / long-lived API keys — the daemons authenticate as
  the user's own account for now (see §7).

## 4. Architecture

The backend stays deployed in the cloud (HF Spaces + Supabase + Groq), unchanged
except for the additive endpoints in §6. Two new outbound-only Python daemons run
on the monitored host.

```
 [attacker]  --hydra ssh-->  [monitored host :22]
                                   | writes
                                   v
                            /var/log/auth.log
                                   | tail + threshold rule
                    +--------------v---------------+
                    |  tb-collector (new)          |
                    |  source adapter -> detection |
                    |  normalizer -> TriageInput   |
                    |  emitter -> POST (JWT)        |
                    +--------------+---------------+
                                   | POST /api/v1/ingest/event
                                   v
              +--------------------------------------------+
              |  EXISTING cloud backend (additive changes) |
              |  run_full_pipeline():                       |
              |  Triage -> Intel -> Investigation ->        |
              |  Response -> Forensics -> Compliance        |
              |  => threat + incident + approval row        |
              +--------------------+-----------------------+
                                   |
                    human opens /approvals, clicks Approve
                    (POST /playbooks/approvals/{id}/decision)
                                   |
                                   v
                    +------------------------------+
                    |  tb-executor (new)           |
                    |  poll approved+unexecuted     |
                    |  block_ip actions             |
                    |  run iptables (guarded)       |
                    |  report execution result      |
                    +--------------+---------------+
                                   v
                       attacker IP really blocked
```

**Universal interface principle:** the `TriageInput` event schema is the one
contract every collector targets. A collector's only job is "turn my system's
raw signals into a `TriageInput` and POST it." Build the boundary once; add
collectors forever.

## 5. Components

### 5.1 `tb-collector` (new, standalone — the flagship reusable piece)

Location: new top-level `collector/` directory (its own package, deployable
independently of the backend; installable on any monitored host).

Responsibilities and internal units:

- **Source adapter** (pluggable). Interface: a class exposing
  `iter_detections() -> Iterator[Detection]`. First implementation
  `AuthLogSSHBruteForce`:
  - Tails `/var/log/auth.log` (follows rotation).
  - Regex-matches failed SSH auth lines, extracting `source_ip` and `username`.
  - Maintains a per-`source_ip` sliding window (default: >= 10 failures within
    60s → detection). Configurable threshold/window.
  - Cooldown per IP (default 300s) so one sustained attack produces one event,
    not dozens.
- **Normalizer.** Maps a `Detection` → `TriageInput`:
  - `title`: e.g. "SSH brute-force from <ip>"
  - `event_type`: `authentication`
  - `source`: `threatbrain-collector/auth.log`
  - `source_ip`, `username`
  - `raw_data`: `{failed_count, window_seconds, sample_lines[], first_seen, last_seen}`
- **Emitter.** Authenticates (see §7), `POST`s to `/api/v1/ingest/event`,
  retries with exponential backoff, re-authenticates on 401, spools detections
  to a bounded local disk queue if the backend is unreachable (drop-oldest on
  overflow).
- **Runner.** `python -m tb_collector --config collector.yaml`; ships with a
  systemd unit file.

Config (`collector.yaml`): backend base URL, account email/password (or token
file), organization is implied by the account, list of sources (each = log path
+ adapter name + thresholds), executor toggle.

### 5.2 `tb-executor` (new, standalone)

Location: `collector/` package (same repo/dir, separate entrypoint
`python -m tb_executor`).

Responsibilities:

- Poll `GET /api/v1/playbooks/approvals?status=approved&action_type=block_ip&pending_execution=true`
  every N seconds (default 10s).
- For each returned action: run `iptables -A INPUT -s <ip> -j DROP`
  (or `ufw deny from <ip>` if configured), idempotently (skip if a matching rule
  already exists).
- Report the outcome via `POST /api/v1/playbooks/approvals/{id}/execution`
  (`executed` or `failed` + detail).
- **Safety guard** (a dedicated, unit-tested unit):
  - Only acts on `action_type == block_ip`.
  - Validates `target` is a well-formed **public** IPv4/IPv6 address.
  - Refuses to block loopback, RFC1918/private ranges, link-local, and a
    configurable allowlist (the host's own management IP / the user's IP).
  - `--dry-run` mode logs the command instead of running it.
- Never crashes on an `iptables` error: marks the action `failed`, logs, continues.

### 5.3 Backend additions (minimal, additive — no rewrites)

See §6.

## 6. Backend changes

### 6.1 New ingest endpoint

New router `app/api/v1/endpoints/ingest.py`, mounted at `/api/v1/ingest`.

- `POST /api/v1/ingest/event`
  - Auth: `require_analyst` (owner satisfies this).
  - Body: `{ event: TriageInput, source_system?: str, collector_id?: str,
    pipeline_flags?: {...} }` — a thin, stable wrapper.
  - Behavior: calls the existing `run_full_pipeline(...)` with sensible defaults
    (`promote_threats=true`, all reactive stages on). Returns the same
    `{stages, summary}` shape.
  - Rationale for a dedicated endpoint (vs. reusing `/orchestrator/handle-event`):
    gives collectors a purpose-named contract decoupled from orchestrator
    internals, and a single place to later add batching/queueing without breaking
    collectors.

### 6.2 Executor-facing approval endpoints (extend `playbooks.py`)

- Extend `GET /playbooks/approvals` with optional query params:
  `action_type` (filter) and `pending_execution` (bool; when true, return only
  rows with `status='approved'` and `execution_status IS NULL`).
- New `POST /playbooks/approvals/{id}/execution`
  - Auth: `require_analyst` (the executor account).
  - Body: `{ result: "executed" | "failed", detail?: str }`.
  - Updates `execution_status`, `executed_at`, `execution_detail`; writes an
    `audit_logs` row (`action = "response.block_ip.executed"` / `.failed`,
    `actor_type = "system"`).
  - 409 if the row is not `approved`, or already has a terminal
    `execution_status`.

### 6.3 Migration `021_approval_execution_state.sql`

Add to `public.playbook_approvals`:

- `execution_status TEXT` (nullable; CHECK in `('executed','failed')` when set)
- `executed_at TIMESTAMPTZ`
- `execution_detail TEXT`

Human decision state (`status`) stays separate from execution state — do not
overload `status`.

### 6.4 "Block Malicious IP" playbook — already exists, verify only

No work required. `011_playbooks.sql` already seeds a `Block Malicious IP`
playbook (category `containment`) for every org via the
`handle_new_organization` trigger, and the orchestrator runs the Response agent
in dry-run, which inserts a `pending` `playbook_approvals` row for the chosen
action regardless of the playbook's `auto_execute`/`approval_required` flags.
Verification step only: confirm a brute-force run produces a `block_ip` approval
row. (Optional future hardening: flip the seeded playbook to
`auto_execute=false, approval_required=true` to make its config match the
human-in-the-loop intent, but it is not needed — the executor only ever acts on
rows a human approved.)

## 7. Authentication model

The collector and executor authenticate as **the user's own ThreatBrain account**
via the existing `POST /api/v1/auth/login`, which returns an access token (owner
role already satisfies `require_analyst`). They cache the access token and
re-login on any 401. Credentials live in the daemon config file (chmod 600).

No new auth infrastructure, no refresh endpoint, no user-invite feature. Dedicated
service accounts and long-lived API keys are a noted future hardening step.

## 8. Error handling

- **Pipeline:** already fault-tolerant per stage (each stage wrapped in
  try/except in `orchestrator_service.py`); one agent failing never kills a run.
- **Collector:** spools to disk on backend outage; dedupes/cooldowns per IP;
  skips + counts malformed log lines; re-authenticates on 401.
- **Executor:** never crashes on `iptables` failure (marks `failed`, continues);
  idempotent rule application; safety guard rejects unsafe targets; keeps polling
  through backend outages.
- **Ingest endpoint:** invalid `TriageInput` → 422 (Pydantic), surfaced to the
  collector logs.

## 9. Testing

### Unit tests
- `AuthLogSSHBruteForce`: sample `auth.log` lines → correct detection (IP,
  username, count); threshold and cooldown behavior; log-rotation handling.
- Normalizer: `Detection` → a valid `TriageInput` (round-trips Pydantic).
- Executor safety guard: rejects loopback/private/link-local/allowlisted IPs;
  accepts a public IP; idempotent rule check.
- Backend: ingest endpoint happy path + 422; execution endpoint state machine
  (approved→executed, 409 on non-approved/terminal).

### Live end-to-end (the real proof)
1. Run `tb-collector` on Kali pointing at the backend, watching `auth.log`.
2. From the attacker machine: `hydra -l root -P <small-wordlist> ssh://<kali-ip>`.
3. Confirm: a new threat + incident appear; Threat Intel enriches the attacker IP
   via AbuseIPDB; Response queues "Block Malicious IP" in `/approvals`.
4. Approve it in the web UI.
5. Confirm `tb-executor` runs the `iptables` DROP and the attacker IP is blocked
   (hydra connections time out); verify the audit trail shows detect → recommend
   → approve → execute.

## 10. Milestones

1. **M1 — Backend seams:** migration 021, ingest endpoint, executor
   endpoints. Verifiable with `curl` before any daemon exists.
2. **M2 — Collector:** source-adapter interface + SSH brute-force adapter +
   normalizer + emitter + auth. Test by tailing a sample log and hitting a local
   backend.
3. **M3 — Executor:** poll loop + safety guard + iptables + reporting.
4. **M4 — Live validation:** the hydra end-to-end run on Kali.
5. **M5 (optional) — nmap adapter:** second source adapter, same interface.

## 11. Open questions / future

- Scaling to a busy real site: add a queue + async worker behind
  `/ingest/event`, run the heavy pipeline only on escalated detections.
- Additional collectors (in-app SDK, nginx/web-log adapter, cloud-audit webhook)
  against the same `TriageInput` contract.
- Dedicated machine identities (service accounts / API keys) replacing
  user-credential auth.
