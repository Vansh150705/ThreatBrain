# Changelog

## Unreleased - enterprise SOC platform (branch `claude/funny-wozniak-ifkwdc`, not pushed, not released)

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
