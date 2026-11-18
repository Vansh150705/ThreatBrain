# Production deployment verification

Every row says what was actually run, where, and what that does **not** prove. "Verified" means executed here with the stated fidelity; nothing is claimed from a mock that is described as live.
Re-run everything that can run with `python3 scripts/release_gates.py --db [--e2e]`; the machine-readable record is `docs/reports/release-report.json`.

Environment of these runs: a sandboxed Linux container (no internet beyond a proxy, no cloud credentials), Docker daemon (vfs storage, host networking only), PostgreSQL 16 scratch server, Python 3.11.

## Summary

| Blocker | Status | Evidence |
|---|---|---|
| Backend Docker image builds | **Verified** | `docker build backend` succeeded (base `python:3.11-slim`; in this sandbox the base was re-tagged locally with the proxy CA added so `pip` could verify TLS; no verification was disabled). Image size 211 MB |
| Backend image runs hardened | **Verified** | `scripts/docker_smoke.py`: read-only rootfs, tmpfs `/tmp`, all capabilities dropped, `no-new-privileges`, non-root user; `GET /api/v1/health` -> 200 |
| Compose files are valid | **Verified (syntax/interpolation only)** | `docker compose -f docker-compose.yml config -q`, same for `docker-compose.prod.yml` |
| Frontend image, nginx, full compose stack | **NOT verified** | Docker Hub rate limit blocked pulling `node`, `nginx`, `postgres`, `postgrest`, `gotrue`; the stack has never been started here |
| Live Supabase (PostgREST, GoTrue, Realtime, RLS through PostgREST) | **NOT verified** | No project/credentials. An attempt to fetch and run a PostgREST binary was blocked by the sandbox policy and was not worked around. Application tests use an in-memory PostgREST stand-in; SQL is verified on plain PostgreSQL 16 with stand-in `auth` objects |
| PostgreSQL migrations, security, queue, ops | **Verified on PostgreSQL 16** | `verify_migrations.sh` (all 27 migrations + seed), `test_queue.sh`, `test_security.sh` (31 checks), `test_ops.sh` (26 checks) |
| PostgreSQL workload and recovery | **Verified (small scale)** | `database/tests/test_workload.sh` (9 checks, below) |
| Backup / restore / migration rollback | **Verified on PostgreSQL 16** | `test_ops.sh`: checksum-verified dump, tampered dump refused, atomic restore, `025` and `027` down scripts then re-apply (`026_down.sql` exists but is not exercised by a test) |
| JWKS / OIDC token verification | **Verified against a local HTTP issuer; hosted IdP NOT verified** | `tests/test_oidc_real_http.py` (8): a real HTTP server serves a JWKS built from locally generated keys. Keys fetched over HTTP and cached; key rotation picked up without restart; IdP outage keeps known keys working but never trusts unknown ones; cold start during an outage fails closed; garbage / oversized / redirecting JWKS responses never authenticate anyone; a slow IdP cannot hang authentication (5 s fetch timeout). Not tested against Supabase's or any hosted IdP's real endpoint |
| Live LLM provider | **NOT verified** | No credentials; agent evaluation uses scripted back-ends (`docs/AGENT_EVALUATION.md`). Live mode is not implemented |
| Connector reliability (threat-intel feeds, notifier) | **Verified with fault injection, not against vendors** | `tests/test_connector_reliability.py` (17): per-feed faults (429, 5xx, timeouts, resets, truncated/bad JSON) degrade only that feed; transport errors retried a bounded number of times; rate-limited/unauthorised feeds reported, not retried; all feeds down gives a clean empty result; oversized responses refused unparsed (2 MB streamed cap); the pipeline still files a threat with every feed down; the Discord notifier survives transport failures. Real feeds (VirusTotal, AbuseIPDB, OTX, ...) were not contacted |
| Safe executor validation | **Verified in a disposable namespace; production firewall/host NEVER touched** | `collector/tests/test_executor_sandbox.py` (13), below |
| Production-scale performance | **NOT verified** | Only `bench/perf.py` on this container (engine ~2 ms p95 per scenario) and the PostgreSQL workload below |
| Deployment / rollback procedure | **Partially verified** | Schema: migrate/rollback/backup/restore tested. Application: image is immutable and re-deployable by tag; a rolling deploy on a real orchestrator was not performed |
| Compliance certification | **None claimed** | No SOC 2 / ISO 27001 assessment has been performed |

## Executor in a disposable environment

`collector/tests/test_executor_sandbox.py` runs the **real** `ActionDispatcher` with the real `IptablesBlocker`, `ip6tables` and `LinuxUserDisabler` inside `unshare --net --mount`: a fresh
network namespace (so `iptables` rules exist only there) and a bind-mounted **copy** of `/etc` (so `usermod -L` edits only the copy). The test asserts afterwards that the host's `iptables -S INPUT`
and `/etc/passwd`/`/etc/shadow` are byte-identical to before. It skips, visibly, unless it is root with `unshare`, `iptables`, `ip6tables`, `usermod`, `useradd` available.

Verified there: a public attacker IP is blocked once, a second block reports "already blocked" (idempotent); private, loopback, allow-listed, malformed, option-injection (`-j ACCEPT`), `/8` and `0.0.0.0/0`
targets are refused **before any command runs**; a /24 and an IPv6 address go to the right tool; a user is locked (`!` prefix in shadow) while `root`, allow-listed and `-h`-style names are refused; an action the operator did not enable does nothing; dry-run changes no rule.
Not verified: Windows (`netsh` / `net user`), nftables-only hosts, the executor's polling/approval protocol against a live server (mocked in `test_executor_client.py`), behaviour on a real fleet. The server never executes actions; they require human approval.

## PostgreSQL workload and failure recovery (`database/tests/test_workload.sh`, 9 checks, all pass)

| Check | Result |
|---|---|
| 3000 jobs, 12 concurrent workers claiming in batches of 20 and completing | each claimed and completed exactly once (`attempts = 1` for all); ~1.7k jobs/s on the scratch server with a `psql` process per claim. Indicative only |
| Worker connection `SIGKILL`ed while idle in the claim transaction | the claim rolls back; a survivor claims all 60 jobs; no attempt is burned |
| Worker killed after its claim committed | jobs under a live lease are not stolen; after the lease expires another worker takes all 40, counted as attempt 2 (poison jobs still reach dead-letter) |
| 16 workers racing to report one correlation | exactly one wins (primary-key ledger, migration 026) |
| 12 writers x 15 compare-and-swap increments on a behaviour profile | final count 180, version advanced exactly 180 times: no lost update |

A finding worth knowing: a worker killed while its database backend is still *executing a long statement* is not noticed by PostgreSQL until the statement ends, so its row locks persist for that time.
`claim_jobs` uses `SKIP LOCKED`, so other workers keep going, but set `client_connection_check_interval` (PostgreSQL 14+) and short statement timeouts in production.
Not tested: replication/failover, PgBouncer or the Supabase pooler (transaction pooling changes the idle-in-transaction behaviour above), and sustained multi-hour load.

## What a first real deployment must still do (checklist, not yet done)

1. Run the full compose stack on a host with registry access; confirm frontend -> nginx -> backend -> Supabase works and `GET /api/v1/ready` is green.
2. Apply migrations to the real Supabase project with `database/migrate.sh`, run `database/tests/test_security.sh` against a clone, take and restore a backup there.
3. Point `SUPABASE_URL` at the real project; confirm asymmetric JWKS verification with a real access token; confirm RLS through PostgREST with two tenants.
4. Configure one real LLM provider in a non-production tenant; build and run the live agent evaluation (not implemented yet); decide the spend cap.
5. Install `tb-collector`/`tb-executor` on a lab host (dry-run first), then a disposable VM for live actions. Never first-run live actions on production.
6. Shadow-run the behavioural layer (`sensitivity: low`) for 2+ weeks before relying on it.
