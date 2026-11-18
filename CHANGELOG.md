# Changelog

## Unreleased - final validation phase (same branch; not pushed, not released)

### Added
- **Deobfuscation layer** (`app/detection/deobfuscate.py`) feeding every rule decoded views of command lines and web fields; identity canonicalisation at ingest; `signal` rule tier; correlation selectors by rule/tactic/tag; 25 new rules (126 total) and 3 correlations (17).
- **Behavioural analytics** (`app/behavior`, migration 027, `/api/v1/behavior/*`, Behaviour page): tenant-specific baselines, peers, cold-start gating, anti-poisoning, corroboration, alert budgets, analyst feedback. See `docs/BEHAVIORAL_ANALYTICS.md`.
- **Agent safeguards**: evidence grounding, ATT&CK-id validation, confidence caps, response-target validation, secret/prompt redaction, cooperative stage cancellation; provenance in stored records and in the triage panel.
- **Validation**: split registry with frozen held-out sets, leakage review, Atomic Red Team and LOLBAS imports (text only), metamorphic and degraded-telemetry experiments, behaviour noise simulation, agent evaluation harness with scripted hostile back-ends, per-split reports.
- **Reliability tests**: real-HTTP OIDC/JWKS, connector fault injection, response size cap, executor in a disposable namespace, PostgreSQL workload and kill-recovery, backend image hardened-run smoke test.
- Docs: BEHAVIORAL_ANALYTICS, AGENT_EVALUATION, reports for detection-gap remediation, attack simulation, false-positive analysis, ATT&CK coverage, deployment verification.

### Known failing gates (not waived)
- Atomic Red Team high-signal recall: tuning 0.582, blind 0.464 (need 0.60).
- Agent evaluation `reference.expected_calibration_error` 0.1553 (need 0.15).

## Earlier - enterprise SOC platform (branch `claude/funny-wozniak-ifkwdc`, not pushed, not released)

### Added
- **Durable pipeline**: idempotent event store, PostgreSQL job queue (leases, retry/backoff, dead-letter, backpressure with 503 + Retry-After), standalone worker (`python -m app.worker`) or embedded worker, retention purge. Migrations 024-026 (rollback scripts for 025/026).
- **Detection engineering**: 101 ATT&CK-mapped rules with inline tests (compiled, ReDoS-guarded), 14 order-independent exactly-once correlations, per-tenant overrides and custom rules with tests-before-enable, rule versions and rollback, Sigma subset importer, ATT&CK coverage view, Detection Engineering agent (server-verified proposals, drafts only).
- **Identity & access**: member lifecycle with escalation guards, scoped API keys with rotation and usage tracking, HMAC-signed ingestion with replay protection, JWKS and OIDC token verification, token-age policy.
- **Operations**: `/ready`, `/metrics`, `/system/status`, `/system/jobs`, `app.doctor`, Operations console, onboarding checklist, demo campaign, `migrate.sh`/`backup.sh`/`restore.sh`, `docker-compose.prod.yml`.
- **LLM providers**: Groq, any OpenAI-compatible endpoint, or none (rules-only operation); agent run version metadata; prompt-injection containment tests.
- **Validation lab** (`backend/validation`) with gates, held-out rounds, evasion probes, safety model for lab-only emulation; performance harness (`backend/bench`).
- **Release gates**: rewritten CI, `scripts/release_gates.py`, docs (OPERATIONS, SECURITY, DETECTION, VALIDATION, RELEASE).
- Tests: 656 backend (was ~157), 18 frontend component, 19 browser E2E, 3 real-PostgreSQL suites.

### Fixed / hardened
- Mass assignment on organization update; API keys reaching `/me`; cross-tenant rule-version reads; NaN/Infinity/NUL/surrogate inputs causing 500s; enum filter 500s; validation errors echoing input.
- Dependency advisories (fastapi/starlette, PyJWT, cryptography, python-multipart, orjson, python-dotenv, pytest, requests); frontend test tooling upgraded past critical dev advisories.
- Correlation race between concurrent workers (ledger-based exactly-once reporting).
- Migration/restore tooling defects found by testing (see `docs/AUDIT.md`).

### Known gaps
See [docs/RELEASE.md](docs/RELEASE.md) (release blockers) and [docs/VALIDATION.md](docs/VALIDATION.md) (detection gaps).
