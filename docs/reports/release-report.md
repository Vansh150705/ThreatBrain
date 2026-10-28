# Release gate report

* commit `e616bc6` · 2026-10-28T19:35:51Z · python 3.13.17
* **19 passed · 0 failed · 1 skipped**

| Gate | Result | Evidence |
|---|---|---|
| backend: ruff | passed | All checks passed! |
| backend: pytest | passed | 656 passed, 137 warnings in 26.16s |
| validation: engine gates | passed | [engine] attacks 169/169 recall=1.0 precision=1.0 fpr=0.0 mapping=0.9941 chains=1.0/1.0 -> PASS |
| validation: pipeline gates | passed | [pipeline] attacks 169/169 recall=1.0 precision=1.0 fpr=0.0 mapping=0.9941 chains=1.0/1.0 -> PASS |
| backend: pip-audit (installed tree) | passed | No known vulnerabilities found |
| backend: bandit (medium+ severity & confidence) | passed | no medium/high findings |
| collector: pytest | passed | 127 passed in 0.82s |
| frontend: eslint | passed | ✖ 42 problems (0 errors, 42 warnings) |
| frontend: tsc | passed | type-check clean |
| frontend: vitest | passed | 18 passed (18) |
| frontend: production build | passed | built in 1.63s |
| frontend: npm audit (production deps) | passed | found 0 vulnerabilities |
| compose: dev file valid | passed |  |
| compose: prod file valid | passed |  |
| docker: image builds | skipped | no Docker daemon available in this environment |
| database: all migrations on PostgreSQL | passed | every migration applied |
| database: queue semantics | passed | ok   400 jobs claimed exactly once across 8 concurrent workers |
| database: security properties | passed | ---- 22 passed, 0 failed |
| database: migrate / rollback / backup / restore | passed | ---- 23 passed, 0 failed |
| e2e: Chromium against the real app + production bundle | passed | 19 passed, 0 failed |

## Not verified by any gate

* A live Supabase project (PostgREST, GoTrue, Realtime) - tests use an in-memory PostgREST stand-in; SQL is verified on a plain PostgreSQL 16 with stand-in auth objects
* A live LLM provider - agents run against a scripted model; detection quality is measured without it, LLM verdict quality is not measured
* Docker image builds and the production compose stack (unless a daemon was available - see the docker gates)
* tb-executor against a real firewall / host
* Hosted-IdP or Supabase asymmetric JWKS endpoints - verified with locally generated keys only
* Throughput or latency on production-grade infrastructure, multi-node scaling
* Any compliance framework (SOC 2, ISO 27001, ...) - no independent assessment has been performed
