# Security model

What ThreatBrain protects, how, how it was tested, and what it does not do. **No compliance certification is claimed.** ThreatBrain has not
been assessed by an independent auditor against SOC 2, ISO 27001 or any other framework; the controls below can *support* such an assessment, they
are not one.

## 1. Assets and trust boundaries

| Boundary | Untrusted side | Trusted side | Primary controls |
|---|---|---|---|
| Browser -> API | users, XSS in rendered data | API | JWT verification, per-request profile check, RBAC, CORS allow-list, security headers, no `eval`/HTML injection of event data (React escaping) |
| Collector / SIEM -> API | the sending host, anyone who steals a key | API | scoped API keys, optional HMAC signing + replay guard, size/batch limits, schema validation, backpressure |
| Event content -> detection | **attacker-controlled log text** | rule engine | bounded text, ReDoS-guarded rules, compiled matchers, NUL/surrogate/NaN neutralised |
| Event content -> LLM | **attacker-controlled log text** | agents | fencing, schema validation, server-side validation of every consequence, human approval |
| API -> database | API bugs | Postgres | every query filtered by `organization_id`; RLS as defence in depth; append-only audit trigger |
| Approved action -> host | a compromised API/DB | `tb-executor` | server never executes; executor re-guards targets and defaults to dry-run |

Multi-tenancy: the API connects with the Supabase service-role key (it bypasses RLS) and **enforces tenancy in code** - every service query is
scoped by `organization_id` taken from the authenticated principal, never from the request. RLS policies remain for direct client access. A bug in
one query is therefore a cross-tenant bug; this is covered by sweep tests (below), not by the database.

## 2. Authentication

* **Users:** Supabase JWTs. HS256 against the project secret; asymmetric (ES256/RS256) via JWKS with key-id lookup, cache, bounded refresh and stale-key
  tolerance during an IdP outage. The verification algorithm is chosen by the server from configuration, not from the token header (algorithm-confusion
  and `alg=none` are tested). `MAX_TOKEN_AGE_MINUTES` can cap token age below `exp`. The user's profile (role, status, deleted) is re-read on every request,
  so a disabled member is locked out immediately.
* **External OIDC IdP (optional):** configure `OIDC_ISSUER` (https), `OIDC_AUDIENCE`; tokens map to an **already provisioned** user by *verified* email; there is no
  just-in-time provisioning and no trust in the IdP's `sub`. SAML is **not implemented**; SSO through Supabase Auth's providers is a Supabase configuration, not part of this code.
* **Machines:** API keys (`tbk_...`, SHA-256 stored, never recoverable), scopes `ingest` / `executor`, role capped at analyst, optional expiry, revocation, rotation with a
  grace period, last-used time/IP and use count. A key can only reach endpoints that declare its scope (sweep-tested: an ingest key reaches exactly the three ingest routes).
* **Signed ingestion (optional per key):** `X-TB-Timestamp` + `X-TB-Signature: v1=HMAC-SHA256(secret, ts.METHOD.path?query.sha256(body))`. The signing secret is derived from
  `APP_SECRET` and the key id (not stored; shown once). Requests outside +-5 minutes, with a modified body/path/method, or with a signature already seen
  (`replay_guard`) are refused (401/409); if the replay table is unavailable the request is refused (503), never accepted unprotected.

## 3. Authorisation

| Role | Can |
|---|---|
| viewer | read threats, incidents, dashboards, audit; use the read-only copilot |
| analyst | + run agents, ingest manually, triage cases, notes, dry-run/validate rules, request tuning proposals |
| admin | + approve/reject response actions, API keys, custom rules and overrides, members (strictly below own level), org name/billing email, operations pages, demo data |
| owner | + create/modify owners |

Privilege-escalation guards (tested): nobody changes their own role/status; admins cannot touch owners or mint admins; the last active owner cannot be demoted or disabled; plan/status of an
organisation are not self-service; API keys cannot mint or rotate keys and cannot call `/me`. Every state change writes an audit row (actor, action, target, diff).

## 4. Input handling

* Request bodies: 1 MB cap, 50-event batches, `raw_data` <= 60 KB, string/field bounds, IP/hash/enum validation. 422 responses **do not echo the rejected input**. Malformed, deeply nested, NaN/Infinity,
  NUL-containing, lone-surrogate and invalid-UTF-8 bodies never produce a 500 (tested). Enum-typed query filters are validated (an invalid `severity` is a 422, not a database error).
* Detection rules are code that runs on attacker-controlled text: regexes are length-limited, unbounded `.*`/`.+` and nested quantifiers (`(a+)+`) are **rejected at load/save time**, evaluated text is capped at
  20 KB, and the whole built-in set is timed against adversarial inputs (< 1 s worst case across all rules). This is a heuristic guard, not a proof; Python's `re` has no timeout.
* Tenant-supplied rules cannot shadow built-in ids, are drafts until their positive **and** negative tests pass, are versioned, audited and revertible.

## 5. LLM / agent safety

1. **Consequences are validated server-side**: a response action's target must appear in the incident's own evidence; actions are allow-listed, de-duplicated and queued as *pending*.
2. **Human approval** is required for every state-changing action; the server never executes anything. `tb-executor` runs only approved actions, guards IPs/CIDRs/users, defaults to dry-run.
3. **Structured outputs** (Pydantic), bounded retries, and evidence verification (e.g. cited log lines must exist).
4. **Fencing**: untrusted data is wrapped in `<untrusted_data>`; forged closing tags are stripped (tested through the tuning agent with a malicious sample).
5. **Deterministic floor**: rule hits set a minimum severity the model cannot talk down; the *Detection Engineering* agent's proposals are accepted only if replaying them on real false-/true-positive samples
   removes false positives without losing true positives, and are stored as drafts.
6. Every agent run records `app`, `provider`, `model`, a prompt hash and the rule-set version in `agent_runs.input.versions`.

Prompt injection is mitigated, not solved: (1)-(2) are what make a successful injection unprofitable. Treat agent text as untrusted output.

## 6. Data protection

Secrets live in environment variables (never returned by any endpoint; `system/status` is tested to contain none). API keys are hashed. `audit_logs` is append-only by trigger (UPDATE/DELETE raise; TRUNCATE denied to end-user roles).
RLS is enabled on **every** public table (checked on PostgreSQL 16), and the tables holding secrets or internal state (api keys, queue, ledgers, replay guard, heartbeats) have no policy at all. TLS termination, disk
encryption and Supabase-side controls are your deployment's responsibility. Retention defaults and backup guidance: [OPERATIONS.md](OPERATIONS.md).

## 7. How this was tested

| Evidence | Where | Scope |
|---|---|---|
| Route sweeps generated from OpenAPI (every non-public route needs auth; viewer cannot mutate; analyst cannot reach admin routes; key scopes; garbage credentials) | `backend/tests/test_security_adversarial.py` | every operation in the OpenAPI document (74 today) |
| Tenant-isolation sweep (org B vs org A's real objects on every parameterised route; list endpoints leak nothing) | same | all parameterised routes |
| JWT/JWKS/OIDC (alg none, algorithm confusion, wrong aud/iss, expiry, unknown kid, refetch rate limit, stale keys, unverified email) | `tests/test_jwks_oidc.py` | locally generated RSA/EC keys |
| Signing, replay, rotation, member lifecycle | `tests/test_signing_rotation.py`, `tests/test_members.py` | |
| Parser abuse, mass assignment, error hygiene, CORS, headers | `tests/test_security_adversarial.py` | |
| Database: RLS everywhere, tenant isolation as `authenticated`, secret tables hidden, audit immutability | `database/tests/test_security.sh` | real PostgreSQL 16 |
| Dependencies | `pip-audit` (installed tree), `npm audit --omit=dev` | CI `supply-chain` job; 0 known vulnerabilities at the time of the last run |
| Static analysis | `bandit` medium+ | clean |

Defects found by this suite and fixed (see [AUDIT.md](AUDIT.md)): NaN/Infinity request values caused a 500; NUL/lone surrogates could break storage; invalid enum filters caused a 500; org `plan`/`status` were
writable by an admin; API keys could call `/me`; a cross-tenant rule-versions probe returned 200 instead of 404; vulnerable pins (PyJWT, cryptography, starlette, python-multipart, orjson, python-dotenv, requests).

## 8. Known gaps and non-goals

* Tenancy is enforced in application code; a missed filter is a data leak. The sweeps reduce that risk; they do not eliminate it. Consider moving to per-request RLS (user-scoped DB role) if you need a hard guarantee.
* In-memory rate limiting is per process; JWT revocation relies on short expiry plus the per-request profile check.
* No SAML, no SCIM, no MFA enforcement of its own (use Supabase Auth's), no per-field encryption, no WAF.
* The Supabase service-role key is a god key. Store it in a secret manager, rotate it, and keep it off developer laptops.
* `tb-executor` has been tested with mocks and dry-run, **not** against a real firewall. Review its guards before enabling live mode.
* JWKS / OIDC code is verified against locally generated keys, not a live provider. Run a staging check with your IdP.
* Findings from automated sweeps are only as good as the OpenAPI document; internal-only helper endpoints added outside it are not covered.

## 9. Reporting a vulnerability

Open a private security advisory on the repository (or contact the maintainer listed in the README). Please include a reproduction; do not test against systems you do not own.
