# Release gates

A change is releasable when every gate below is green **and** the "not verified" list is understood. The gates are executed by CI
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) and, locally, by one command that also writes a machine-readable report:

```bash
python3 scripts/release_gates.py --python backend/venv/bin/python --db --e2e [--bench]
#   -> docs/reports/release-report.json   (machine-readable, one record per gate: status, evidence, commit, timestamp)
#   -> docs/reports/release-report.md     (human-readable, includes the "not verified" list)
```

A gate that cannot run in the current environment is recorded as `skipped` with the reason; it is never reported as passed.
The script exits non-zero if any executed gate failed.

## Gates

| Gate | Command | Proves | Does **not** prove |
|---|---|---|---|
| Backend lint | `ruff check app tests validation bench` | style/obvious bugs | - |
| Backend tests | `pytest -q` (656) | API, auth, RBAC, tenant isolation sweeps, queue/worker, pipeline, adapters, rules, correlation, signing, security-adversarial cases | behaviour against live Supabase / LLM |
| Detection gates (engine) | `python -m validation.runner --mode engine --gate` | recall >= 0.90, precision >= 0.95, FPR <= 0.03, ATT&CK mapping >= 0.80, campaign chains 1.0, p95 <= 25 ms ([`gates.yaml`](../backend/validation/gates.yaml)) | detection of attacks nobody wrote a scenario for (the corpus is author-written; see [VALIDATION.md](VALIDATION.md)) |
| Detection gates (pipeline) | `python -m validation.runner --mode pipeline --gate` | same scenarios through ingest -> queue -> worker -> correlation -> agents (scripted LLM) | LLM verdict quality |
| Dependency audit | `pip-audit` on the installed tree; `npm audit --omit=dev` | no known advisories at test time | unknown/future advisories; dev-only npm advisories are reported, not gated |
| Static analysis | `bandit -r backend/app -ll -ii` | no medium+ findings | logic flaws |
| Collector tests | `pytest -q` in `collector/` (127) | parsing, spooling, signing client | real hosts |
| Frontend | `npm run lint`, `npx tsc -b`, `npm test` (18), `npm run build` | types, components, bundle builds | visual regressions beyond the E2E |
| Browser E2E | `npm run e2e` (19 checks, Chromium) | login, dashboards, detection console, operations, key rotation, member management against the real app + production bundle | real Supabase Auth |
| Real PostgreSQL | `database/verify_migrations.sh`, `tests/test_queue.sh`, `tests/test_security.sh`, `tests/test_ops.sh` | all migrations apply; queue exactly-once under concurrency; RLS/tenant isolation/append-only audit; migrate runner, drift refusal, rollback, backup/verify/atomic restore | Supabase-specific behaviour (Auth, PostgREST, Realtime) - auth objects are stand-ins |
| Compose | `docker compose [-f docker-compose.prod.yml] config -q` | the files parse and interpolate | that the images build or the stacks run |
| Docker | `docker build ...` | image builds | - (CI only; **never executed in the authoring environment**) |

Optional: `--bench` runs `backend/bench/perf.py` (detection, worker, API ingest, queue claim). Numbers from a shared sandbox are indicative only.

## Release blockers (as of this report)

These are not code defects the gates can find; they must be closed by a person before a production go-live:

1. **Staging run on real infrastructure**: a live Supabase project (migrations 001-026, Auth, PostgREST, Realtime) and the Docker images/production compose stack have never been executed by the authors' tooling.
2. **A live LLM provider** has never been called; agent output quality (as opposed to schema/containment behaviour) is unmeasured.
3. **Independent assessment**: no penetration test, SOC 2 or ISO 27001 assessment exists. The adversarial suite in `backend/tests/test_security_adversarial.py` is self-written.
4. **Detection coverage**: 5 of 12 evasion probes are detected; see [VALIDATION.md](VALIDATION.md) for the open gaps and the first-run held-out numbers (66-73% recall) before trusting the 100% tuned-corpus results.
5. **`tb-executor`** has been exercised only in dry-run/mock; test against a disposable host before enabling approved-action execution.
6. **Scale**: throughput was measured on a 4-vCPU sandbox against an in-memory DB; capacity-plan with your own load.

## Cutting a release

1. `python3 scripts/release_gates.py --db --e2e` on a clean checkout (and CI green).
2. Read `docs/reports/release-report.md`; resolve any `failed`; understand every `skipped`.
3. Apply migrations to staging with `database/migrate.sh --dry-run`, then for real; `python -m app.doctor` must be clean.
4. Update [CHANGELOG.md](../CHANGELOG.md); tag.
