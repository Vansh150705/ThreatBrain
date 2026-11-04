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
| Backend tests | `pytest -q` (815) | API, auth, RBAC, tenant isolation sweeps, queue/worker, pipeline, adapters, rules, correlation, signing, security-adversarial cases | behaviour against live Supabase / LLM |
| Detection gates (engine) | `python -m validation.runner --mode engine --gate` | recall >= 0.90, precision >= 0.95, FPR <= 0.03, ATT&CK mapping >= 0.80, campaign chains 1.0, p95 <= 25 ms ([`gates.yaml`](../backend/validation/gates.yaml)) | detection of attacks nobody wrote a scenario for (the corpus is author-written; see [VALIDATION.md](VALIDATION.md)) |
| Detection gates (pipeline) | `python -m validation.runner --mode pipeline --gate` | same scenarios through ingest -> queue -> worker -> correlation -> agents (scripted LLM) | LLM verdict quality |
| Dependency audit | `pip-audit` on the installed tree; `npm audit --omit=dev` | no known advisories at test time | unknown/future advisories; dev-only npm advisories are reported, not gated |
| Static analysis | `bandit -r backend/app -ll -ii` | no medium+ findings | logic flaws |
| Collector tests | `pytest -q` in `collector/` (127) | parsing, spooling, signing client | real hosts |
| Frontend | `npm run lint`, `npx tsc -b`, `npm test` (26), `npm run build` | types, components, bundle builds | visual regressions beyond the E2E |
| Browser E2E | `npm run e2e` (19 checks, Chromium) | login, dashboards, detection console, operations, key rotation, member management against the real app + production bundle | real Supabase Auth |
| Real PostgreSQL | `database/verify_migrations.sh`, `tests/test_queue.sh`, `tests/test_security.sh` (31), `tests/test_ops.sh` (26) | all migrations apply; queue exactly-once under concurrency; RLS/tenant isolation/append-only audit; migrate runner, drift refusal, rollback, backup/verify/atomic restore | Supabase-specific behaviour (Auth, PostgREST, Realtime) - auth objects are stand-ins |
| Compose | `docker compose [-f docker-compose.prod.yml] config -q` | the files parse and interpolate | that the images build or the stacks run |
| Docker (backend) | `docker build backend` + `scripts/docker_smoke.py` | the image builds and starts under the production hardening profile (read-only rootfs, no capabilities, non-root) and answers `/health` | the frontend image, nginx, the full stack |
| Split evaluation | `validation.freeze --check`, `validation.evaluate --gate`, `validation.leakage --gate` | held-out sets unchanged; per-split detection, false-positive, evasion, behaviour, degraded-telemetry and engine-latency gates (`gates_v2.yaml`) | detection on real traffic; **2 gates currently fail (ART high-signal recall)** |
| Agent evaluation | `validation.agent_eval --gate` | platform guardrails against scripted hostile/faulty model back-ends (`agent_gates.yaml`) | any real model's quality; **1 gate currently fails (reference ECE)** |
| Executor sandbox | `collector/tests/test_executor_sandbox.py` (13) | real iptables/ip6tables/usermod via the dispatcher inside a disposable netns + /etc copy; host untouched | real firewall/host, Windows |
| PostgreSQL workload | `database/tests/test_workload.sh` (9) | exactly-once claiming under 12 workers, SIGKILL recovery, ledger and CAS races | scale, failover, pooler |

Optional: `--bench` runs `backend/bench/perf.py` (detection, worker, API ingest, queue claim). Numbers from a shared sandbox are indicative only.

## Release blockers (as of this report)

These are not code defects the gates can find; they must be closed by a person before a production go-live:

1. **Staging run on real infrastructure**: a live Supabase project (migrations 001-027, Auth, PostgREST, Realtime) and the **frontend image and the full production compose stack** have never been executed by the authors' tooling. (The backend image *has* been built and run under the hardened profile; see [deployment-verification](reports/deployment-verification.md).)
2. **A live LLM provider** has never been called and a live evaluation mode does not exist; agent verdict quality, latency and cost are unmeasured (only the guardrails around scripted models are).
3. **Independent assessment**: no penetration test, SOC 2 or ISO 27001 assessment exists. The adversarial suite in `backend/tests/test_security_adversarial.py` is self-written.
4. **Detection coverage**: 11 of 12 evasion probes are detected (EVA-006 needs a behavioural baseline). On the blind Atomic Red Team half the rule set alerts on 40.7% of procedures (46.4% in high-signal tactics; the 60% gate **fails**); see [VALIDATION.md](VALIDATION.md) section 0 and [attack-simulation](reports/attack-simulation.md). Do not trust the 100% tuned-corpus results.
5. **`tb-executor`** has been exercised live only inside a disposable network+mount namespace (iptables/ip6tables/usermod on a copy of /etc; `collector/tests/test_executor_sandbox.py`), never on a real firewall or host, and never on Windows. Run it in dry-run on a lab VM before enabling approved-action execution.
6. **Scale**: throughput was measured on a 4-vCPU sandbox against an in-memory DB; capacity-plan with your own load.

## Cutting a release

1. `python3 scripts/release_gates.py --db --e2e` on a clean checkout (and CI green).
2. Read `docs/reports/release-report.md`; resolve any `failed`; understand every `skipped`.
3. Apply migrations to staging with `database/migrate.sh --dry-run`, then for real; `python -m app.doctor` must be clean.
4. Update [CHANGELOG.md](../CHANGELOG.md); tag.

## Release-gate status for this build (strict, nothing waived)

`scripts/release_gates.py` is the single entry point; its output is `docs/reports/release-report.{json,md}`. A failed gate stays failed, a skipped gate is recorded as skipped with a reason, and the report lists what no gate verifies.
Thresholds live in `validation/gates_v2.yaml`, `validation/agent_gates.yaml`, `validation/gates.yaml` and were not lowered to pass.

| Area | Gate | Status |
|---|---|---|
| Security findings | bandit medium+ (0), pip-audit (0 known), npm audit prod deps (0), tenant-isolation and adversarial suites | see release report |
| Tenant isolation / authn / authz | backend sweeps over every route, RLS tests on PostgreSQL | pass |
| Database integrity | all 27 migrations, constraints, append-only audit, rollback, backup/restore, workload | pass on PostgreSQL 16 stand-in; **hosted Supabase not verified** |
| Ingestion reliability | queue exactly-once, backpressure, idempotency, worker kill recovery | pass |
| Detection quality | development/tuning/held-out gates | **FAIL: ART high-signal recall (tuning 0.582, held-out 0.464; need 0.60)** |
| False-positive level | per-split benign FP, benign mutation FP, behavioural noise | pass (held-out FP figure is not independent, see false-positive-analysis) |
| Evasion resistance | metamorphic retention, adversarial variants, 11/12 probes | pass |
| Agent evaluation | `agent_gates.yaml` | **FAIL: reference ECE 0.1553 (need 0.15)**; live provider not run |
| Deployment reproducibility | compose config, backend image build + hardened run | pass; **frontend image/full stack not run** |
| Backup / recovery | `test_ops.sh` | pass |
| API / frontend | pytest 815, vitest 26, Playwright 19, eslint 0 errors, tsc | see release report |

**Verdict: not release-ready.** Two measurable gates fail and the blockers above are open. This is a candidate for a staged pilot (shadow mode, no automatic actions), not for an unsupervised enterprise rollout.
