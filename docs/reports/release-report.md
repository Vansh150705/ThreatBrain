# Release gate report

* commit `1384acd` · 2026-11-04T07:50:58Z · python 3.11.17
* **26 passed · 2 failed · 0 skipped**

| Gate | Result | Evidence |
|---|---|---|
| backend: ruff | passed | All checks passed! |
| backend: pytest | passed | 815 passed, 146 warnings in 41.87s |
| validation: engine gates | passed | [engine] attacks 169/169 recall=1.0 precision=1.0 fpr=0.0 mapping=0.9941 chains=1.0/1.0 -> PASS |
| validation: pipeline gates | passed | [pipeline] attacks 169/169 recall=1.0 precision=1.0 fpr=0.0 mapping=0.9941 chains=1.0/1.0 -> PASS |
| validation: dataset freeze intact | passed | frozen datasets unchanged: heldout_v3.yaml, heldout_v3_chains.yaml, adversarial_unseen.yaml, behavior_heldout.yaml, heldout_v4.yaml, heldout_v4_chains.yaml, behavior_heldout_v4.yaml, art_derived.yaml#blind |
| validation: split evaluation gates (detection, FP, evasion, behaviour) | failed | evaluation: 30/32 gates passed; freeze intact; FAILED: heldout.art_high_signal_recall: 0.4641 (need >= 0.6) | tuning.art_high_signal_recall: 0.582 (need >= 0.6) |
| validation: train/held-out leakage review | passed | leakage gates: PASS |
| validation: agent evaluation gates (scripted + adversarial back-ends) | failed | agent evaluation: 17/18 gates passed; live provider: not_run; FAILED: reference.expected_calibration_error: 0.1553 (need <= 0.15) |
| validation: ATT&CK coverage matrix regenerated | passed | 83/228 parent techniques have a rule; 156/715 including sub-techniques |
| backend: pip-audit (installed tree) | passed | No known vulnerabilities found |
| backend: bandit (medium+ severity & confidence) | passed | no medium/high findings |
| collector: pytest (incl. executor in a disposable namespace) | passed | 140 passed in 0.93s |
| frontend: eslint | passed | ✖ 43 problems (0 errors, 43 warnings) |
| frontend: tsc | passed | type-check clean |
| frontend: vitest | passed | 26 passed (26) |
| frontend: production build | passed | built in 1.42s |
| frontend: npm audit (production deps) | passed | found 0 vulnerabilities |
| compose: dev file valid | passed |  |
| compose: prod file valid | passed |  |
| docker: backend image builds | passed |  |
| docker: backend image runs hardened (read-only rootfs, no caps, non-root) and answers /api/v1/health | passed | image runs hardened: HTTP 200 {"status": "ok", "service": "ThreatBrain", "version": "0.1.0", "environment": "development", "timestamp_unix": 179377849; read-only rootfs, caps dropped, no-new-privileges, non-root user |
| database: all migrations on PostgreSQL | passed | every migration applied |
| database: queue semantics | passed | ok   400 jobs claimed exactly once across 8 concurrent workers |
| database: security properties | passed | ---- 31 passed, 0 failed |
| database: migrate / rollback / backup / restore | passed | ---- 26 passed, 0 failed |
| database: queue workload, worker-kill recovery, concurrent writers | passed | ---- 9 passed, 0 failed |
| e2e: Chromium against the real app + production bundle | passed | 19 passed, 0 failed |
| benchmark | passed | detection          880.2 events/s  p95 2.786 ms  (126 rules) |

## Failed gates (not waived, thresholds unchanged)

* **validation: split evaluation gates (detection, FP, evasion, behaviour)**: evaluation: 30/32 gates passed; freeze intact; FAILED: heldout.art_high_signal_recall: 0.4641 (need >= 0.6) | tuning.art_high_signal_recall: 0.582 (need >= 0.6)
* **validation: agent evaluation gates (scripted + adversarial back-ends)**: agent evaluation: 17/18 gates passed; live provider: not_run; FAILED: reference.expected_calibration_error: 0.1553 (need <= 0.15)

## Not verified by any gate

* A live Supabase project (PostgREST, GoTrue, Realtime) - tests use an in-memory PostgREST stand-in; SQL is verified on a plain PostgreSQL 16 with stand-in auth objects
* A live LLM provider - agents run against a scripted model; detection quality is measured without it, LLM verdict quality is not measured
* The frontend image build and the full production compose stack (needs registry access for node/nginx/postgres/postgrest/gotrue base images)
* tb-executor against a real production firewall / fleet, Windows Firewall, nftables-only hosts (the Linux iptables/usermod path IS exercised, but only inside a disposable network+mount namespace)
* Detection quality on real customer traffic - every number is measured on synthetic/derived corpora; the held-out sets are small and were authored by the same team
* LLM latency, token cost and verdict quality under a real provider (the agent evaluation uses scripted back-ends, including adversarial ones)
* Hosted-IdP or Supabase asymmetric JWKS endpoints - verified with locally generated keys only
* Throughput or latency on production-grade infrastructure, multi-node scaling
* Any compliance framework (SOC 2, ISO 27001, ...) - no independent assessment has been performed
