# Real Attack Ingestion — Phase 1 (Backend Seams) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the three additive backend pieces that let external collectors feed real events into ThreatBrain and let an executor report that an approved block was carried out — with no changes to the existing pipeline.

**Architecture:** A new `/api/v1/ingest/event` endpoint wraps the existing `run_full_pipeline()`. The existing `playbook_approvals` table gains execution-state columns (migration 021). The existing `playbooks.py` router gains executor-facing filters on the list endpoint plus a new "report execution" endpoint. Everything else (agents, orchestrator, auth, RLS) is untouched.

**Tech Stack:** FastAPI 0.115, Pydantic v2, Supabase (Postgres) via supabase-py 2.10, structlog. Backend runs from `backend/` with `./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000`.

## Global Constraints

- Backend deploys from `backend/.git` to Hugging Face Spaces; the root repo (`origin`) is Vercel + history. A backend change is live only after pushing to **both** remotes (see `DEPLOY.md`). This plan does **not** push; it stops at local verification.
- SQL migrations are applied **by hand** in the Supabase SQL editor — they do not auto-run. Run the migration **before** the backend code that depends on it.
- Commit style: Conventional Commits (`feat:`, `fix:`, `chore:`). **Never** add a Claude co-author or mention Claude in commit messages.
- Verification convention for this phase: `curl` against a locally running backend (the repo has no pytest harness). Every task ends with concrete curl commands and expected output.
- Auth for all new endpoints reuses the existing `require_analyst` / `get_current_user` dependencies. No new auth code.

---

### Task 1: Migration 021 — execution-state columns on `playbook_approvals`

Adds columns so an approved action can be marked as really executed (or failed) on the monitored host, kept separate from the human decision `status` (`pending|approved|rejected`).

**Files:**
- Create: `database/migrations/021_approval_execution_state.sql`

**Interfaces:**
- Consumes: existing `public.playbook_approvals` table (from `017_playbook_approvals.sql`), columns `id, organization_id, status, action_type`.
- Produces: new columns `execution_status TEXT` (nullable, CHECK in `('executed','failed')`), `executed_at TIMESTAMPTZ`, `execution_detail TEXT`; partial index `idx_playbook_approvals_pending_execution`.

- [ ] **Step 1: Write the migration file**

Create `database/migrations/021_approval_execution_state.sql`:

```sql
-- 021_approval_execution_state.sql
-- Track whether an approved action has actually been carried out on the
-- monitored host by tb-executor. Execution state is kept separate from the
-- human decision state (`status`), which stays pending|approved|rejected.

ALTER TABLE public.playbook_approvals
  ADD COLUMN IF NOT EXISTS execution_status  TEXT,
  ADD COLUMN IF NOT EXISTS executed_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS execution_detail  TEXT;

ALTER TABLE public.playbook_approvals
  DROP CONSTRAINT IF EXISTS playbook_approvals_execution_status_check;

ALTER TABLE public.playbook_approvals
  ADD CONSTRAINT playbook_approvals_execution_status_check
  CHECK (execution_status IS NULL OR execution_status IN ('executed', 'failed'));

COMMENT ON COLUMN public.playbook_approvals.execution_status IS
  'NULL = not yet executed; executed | failed once tb-executor has acted.';
COMMENT ON COLUMN public.playbook_approvals.executed_at IS
  'When tb-executor carried out (or failed) the action.';
COMMENT ON COLUMN public.playbook_approvals.execution_detail IS
  'Free-form detail from the executor (e.g., iptables rule added, or error text).';

-- The executor polls for approved + not-yet-executed actions of a given type.
CREATE INDEX IF NOT EXISTS idx_playbook_approvals_pending_execution
  ON public.playbook_approvals(organization_id, action_type)
  WHERE status = 'approved' AND execution_status IS NULL;
```

- [ ] **Step 2: Apply the migration in Supabase**

Open the Supabase Dashboard → SQL Editor, paste the full contents of the new file, and run it. Expect: "Success. No rows returned."

- [ ] **Step 3: Verify the columns and index exist**

In the same SQL editor, run:

```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'playbook_approvals'
  AND column_name IN ('execution_status', 'executed_at', 'execution_detail')
ORDER BY column_name;

SELECT indexname
FROM pg_indexes
WHERE tablename = 'playbook_approvals'
  AND indexname = 'idx_playbook_approvals_pending_execution';
```

Expected: first query returns 3 rows (`executed_at | timestamp with time zone`, `execution_detail | text`, `execution_status | text`); second returns 1 row.

- [ ] **Step 4: Verify the CHECK constraint rejects bad values**

```sql
-- should fail with a check-constraint violation
UPDATE public.playbook_approvals SET execution_status = 'bogus' WHERE false;
```

Expected: because `WHERE false` matches no rows this returns "0 rows"; to truly prove the constraint, instead run this harmless probe which must raise:

```sql
DO $$
BEGIN
  BEGIN
    INSERT INTO public.playbook_approvals
      (organization_id, playbook_name, action_type, target, execution_status)
    VALUES
      ('00000000-0000-0000-0000-000000000000', 'x', 'block_ip', '1.2.3.4', 'bogus');
    RAISE EXCEPTION 'constraint did not fire';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'OK: execution_status check constraint works';
  WHEN foreign_key_violation THEN
    RAISE NOTICE 'OK: reached FK check, constraint ordering fine';
  END;
END$$;
```

Expected: a `NOTICE: OK: ...` message, not a raised "constraint did not fire".

- [ ] **Step 5: Commit**

```bash
git add database/migrations/021_approval_execution_state.sql
git commit -m "feat(db): add execution-state columns to playbook_approvals"
```

---

### Task 2: Ingest endpoint — `POST /api/v1/ingest/event`

The universal front door. Accepts one normalized `TriageInput` event plus optional source metadata and runs the full pipeline, returning the same `{stages, summary}` shape as the orchestrator.

**Files:**
- Create: `backend/app/api/v1/endpoints/ingest.py`
- Modify: `backend/app/api/v1/router.py`

**Interfaces:**
- Consumes: `run_full_pipeline(*, organization_id, event, ...)` from `app.services.orchestrator_service`; `TriageInput` from `app.agents.triage`; `require_analyst`, `CurrentUser` from `app.api.deps`.
- Produces: route `POST /api/v1/ingest/event` with request body `IngestEventRequest { event: TriageInput, source_system?: str, collector_id?: str }` and response `IngestEventResponse { stages: dict, summary: dict }`.

- [ ] **Step 1: Write the ingest router**

Create `backend/app/api/v1/endpoints/ingest.py`:

```python
"""Universal ingestion front door for external collectors (tb-collector, SDKs, webhooks)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from app.agents.triage import TriageInput
from app.api.deps import CurrentUser, require_analyst
from app.core.logging import get_logger
from app.services.orchestrator_service import run_full_pipeline

router = APIRouter(prefix="/ingest", tags=["ingest"])
log = get_logger(__name__)


class IngestEventRequest(BaseModel):
    event: TriageInput
    source_system: str | None = Field(
        default=None,
        description="Name of the sending collector/source, e.g. 'tb-collector/auth.log'.",
    )
    collector_id: str | None = Field(
        default=None,
        description="Stable identifier of the collector instance that sent this.",
    )


class IngestEventResponse(BaseModel):
    stages: dict[str, Any]
    summary: dict[str, Any]


@router.post(
    "/event",
    response_model=IngestEventResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest one real security event and run the full agent pipeline",
)
async def ingest_event(
    request: IngestEventRequest,
    user: CurrentUser = Depends(require_analyst),
) -> IngestEventResponse:
    """Accept a normalized event from an external collector and run the pipeline."""
    log.info(
        "ingest_event_received",
        source_system=request.source_system,
        collector_id=request.collector_id,
        source_ip=request.event.source_ip,
        event_type=request.event.event_type,
    )
    result = run_full_pipeline(
        organization_id=user.organization_id,
        event=request.event,
    )
    return IngestEventResponse(**result)
```

- [ ] **Step 2: Mount the router**

In `backend/app/api/v1/router.py`, add `ingest` to the imports and include it. Change the import block:

```python
from app.api.v1.endpoints import (
    agents,
    audit,
    auth,
    copilot,
    incidents,
    ingest,
    meta,
    orchestrator,
    organizations,
    playbooks,
    stats,
    threats as threats_endpoints,
)
```

And add this include near the orchestrator include:

```python
# Ingest (universal collector front door)
api_router.include_router(ingest.router)
```

- [ ] **Step 3: Start the backend and get a token**

Run the backend (from `backend/`):

```bash
./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000
```

In a second shell, log in with your ThreatBrain account to get a token (replace creds):

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"YOU@example.com","password":"YOUR_PASSWORD"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])"
```

Copy the printed token into a shell variable: `TOKEN=<paste>`.

- [ ] **Step 4: Verify the happy path (200 + pipeline runs)**

```bash
curl -s -X POST http://localhost:8000/api/v1/ingest/event \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "source_system": "tb-collector/auth.log",
        "collector_id": "kali-lab-01",
        "event": {
          "title": "SSH brute-force from 203.0.113.42",
          "description": "42 failed SSH logins for user root within 60s.",
          "source": "authentication",
          "event_type": "authentication.brute_force",
          "source_ip": "203.0.113.42",
          "username": "root",
          "raw_data": {"failed_count": 42, "window_seconds": 60}
        }
      }' | python -m json.tool
```

Expected: HTTP 200 JSON with a `stages` object containing `triage` (status `ok`) and a `summary` object with `stages_succeeded >= 1`. A new threat should now appear in the dashboard `/threats`.

- [ ] **Step 5: Verify auth is enforced (401 without token)**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://localhost:8000/api/v1/ingest/event \
  -H "Content-Type: application/json" \
  -d '{"event":{"title":"x"}}'
```

Expected: `401`.

- [ ] **Step 6: Verify validation (422 on a malformed event)**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  http://localhost:8000/api/v1/ingest/event \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event":{"description":"missing required title"}}'
```

Expected: `422` (Pydantic rejects the missing required `title`).

- [ ] **Step 7: Commit**

```bash
git add backend/app/api/v1/endpoints/ingest.py backend/app/api/v1/router.py
git commit -m "feat(api): add universal /ingest/event endpoint for external collectors"
```

---

### Task 3: Executor approval endpoints (extend `playbooks.py`)

Give the executor (a) a way to list approved-but-unexecuted `block_ip` actions and (b) a way to report the execution result, which flips the new execution columns and writes an audit entry.

**Files:**
- Modify: `backend/app/api/v1/endpoints/playbooks.py`

**Interfaces:**
- Consumes: existing `playbook_approvals` rows with `status='approved'`; new columns from Task 1; `require_analyst` from `app.api.deps`; existing `ApprovalItem` model.
- Produces:
  - `GET /api/v1/playbooks/approvals` gains query params `action_type: str | None` and `pending_execution: bool = False`.
  - `POST /api/v1/playbooks/approvals/{approval_id}/execution` with body `ExecutionReport { result: "executed" | "failed", detail?: str }`, returning `ApprovalItem`.
  - `ApprovalItem` gains fields `execution_status`, `executed_at`, `execution_detail`.

- [ ] **Step 1: Add `require_analyst` to the imports**

In `backend/app/api/v1/endpoints/playbooks.py`, change:

```python
from app.api.deps import CurrentUser, get_current_user, require_admin
```

to:

```python
from app.api.deps import CurrentUser, get_current_user, require_admin, require_analyst
```

- [ ] **Step 2: Expose the new columns on `ApprovalItem`**

In the `ApprovalItem` model, add three fields after `created_at: datetime`:

```python
    execution_status: Optional[str] = None
    executed_at: Optional[datetime] = None
    execution_detail: Optional[str] = None
```

- [ ] **Step 3: Extend the list endpoint with executor filters**

Replace the whole `list_approvals` function with:

```python
@router.get("/approvals", response_model=ApprovalListResponse)
async def list_approvals(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    approval_status: Optional[str] = Query(default=None, alias="status"),
    action_type: Optional[str] = Query(default=None),
    pending_execution: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
) -> ApprovalListResponse:
    """List the approval queue for the user's org, newest first.

    Executor filters: `action_type` narrows to one action (e.g. block_ip);
    `pending_execution=true` returns only approved actions not yet executed.
    """
    admin = get_supabase_admin()
    query = (
        admin.table("playbook_approvals")
        .select("*", count="exact")
        .eq("organization_id", user.organization_id)
    )
    if pending_execution:
        query = query.eq("status", "approved").is_("execution_status", "null")
    elif approval_status:
        query = query.eq("status", approval_status)
    if action_type:
        query = query.eq("action_type", action_type)

    result = query.order("created_at", desc=True).limit(limit).execute()
    rows = result.data or []
    return ApprovalListResponse(
        items=[ApprovalItem.model_validate(r) for r in rows],
        total=result.count or 0,
    )
```

- [ ] **Step 4: Add the execution-report model and endpoint**

Add the model next to `DecisionRequest`:

```python
class ExecutionReport(BaseModel):
    result: Literal["executed", "failed"]
    detail: Optional[str] = Field(default=None, max_length=1000)
```

Add this endpoint at the end of the file:

```python
@router.post("/approvals/{approval_id}/execution", response_model=ApprovalItem)
async def report_execution(
    approval_id: str,
    request: ExecutionReport,
    user: Annotated[CurrentUser, Depends(require_analyst)],
) -> ApprovalItem:
    """Record the real-world execution result of an approved action.

    Called by tb-executor after it runs (or fails to run) the block on the host.
    """
    admin = get_supabase_admin()

    rows = (
        admin.table("playbook_approvals")
        .select("*")
        .eq("id", approval_id)
        .eq("organization_id", user.organization_id)
        .limit(1)
        .execute()
    ).data or []
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found.")
    approval = rows[0]

    if approval["status"] != "approved":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Only approved actions can be executed; this one is {approval['status']}.",
        )
    if approval.get("execution_status") is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This action was already {approval['execution_status']}.",
        )

    updated = (
        admin.table("playbook_approvals")
        .update(
            {
                "execution_status": request.result,
                "executed_at": datetime.now(timezone.utc).isoformat(),
                "execution_detail": request.detail,
            }
        )
        .eq("id", approval_id)
        .execute()
    ).data[0]

    # log the real-world action to the append-only audit trail
    try:
        admin.table("audit_logs").insert(
            {
                "organization_id": user.organization_id,
                "actor_type": "system",
                "actor_name": "tb-executor",
                "action": f"response.block_ip.{request.result}",
                "target_type": "incident",
                "target_id": approval.get("incident_id"),
                "target_short_id": approval.get("incident_short_id"),
                "target_name": approval.get("incident_title"),
                "severity": "high" if request.result == "executed" else "info",
                "status": "success" if request.result == "executed" else "failure",
                "reason": request.detail
                or f"{approval['playbook_name']} on {approval['target']} {request.result}.",
                "metadata": {
                    "action_type": approval["action_type"],
                    "target": approval["target"],
                    "execution_status": request.result,
                },
            }
        ).execute()
    except Exception:
        log.exception("execution_audit_log_failed")

    log.info(
        "playbook_execution_reported",
        approval_id=approval_id,
        result=request.result,
    )
    return ApprovalItem.model_validate(updated)
```

- [ ] **Step 5: Restart the backend and create test data**

Restart uvicorn. Reuse `$TOKEN` from Task 2 (re-login if expired). You need one approved `block_ip` approval. If Task 2's ingest run produced a `block_ip` recommendation, list pending ones:

```bash
curl -s "http://localhost:8000/api/v1/playbooks/approvals?status=pending&action_type=block_ip" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

Grab an `id` from the output as `AID=<id>`. Approve it (needs admin/owner — your account is owner):

```bash
curl -s -X POST "http://localhost:8000/api/v1/playbooks/approvals/$AID/decision" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"decision":"approved","note":"lab test"}' | python -m json.tool
```

Expected: JSON with `"status": "approved"`. (If no `block_ip` recommendation exists yet, re-run the Task 2 ingest curl first.)

- [ ] **Step 6: Verify the `pending_execution` filter returns it**

```bash
curl -s "http://localhost:8000/api/v1/playbooks/approvals?pending_execution=true&action_type=block_ip" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

Expected: the approved row appears, with `"execution_status": null`.

- [ ] **Step 7: Verify reporting execution flips the state**

```bash
curl -s -X POST "http://localhost:8000/api/v1/playbooks/approvals/$AID/execution" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"result":"executed","detail":"iptables DROP rule added for 203.0.113.42"}' \
  | python -m json.tool
```

Expected: JSON with `"execution_status": "executed"` and a non-null `executed_at`.

- [ ] **Step 8: Verify it now drops out of the pending filter and rejects double-execution**

```bash
# no longer pending execution
curl -s "http://localhost:8000/api/v1/playbooks/approvals?pending_execution=true&action_type=block_ip" \
  -H "Authorization: Bearer $TOKEN" | python -c "import sys,json;print('count:',json.load(sys.stdin)['total'])"

# second execution report must 409
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  "http://localhost:8000/api/v1/playbooks/approvals/$AID/execution" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"result":"executed"}'
```

Expected: the approved-and-executed row is gone from the pending list; the second report returns `409`.

- [ ] **Step 9: Verify the audit trail recorded the execution**

```bash
curl -s "http://localhost:8000/api/v1/audit?limit=5" \
  -H "Authorization: Bearer $TOKEN" | python -m json.tool
```

Expected: a recent entry with `action` = `response.block_ip.executed`, `actor_name` = `tb-executor`. (If the audit route path differs, open `/audit` in the web UI instead and confirm the entry appears.)

- [ ] **Step 10: Commit**

```bash
git add backend/app/api/v1/endpoints/playbooks.py
git commit -m "feat(api): add executor filters and execution-report endpoint to approvals"
```

---

## Phase 1 Definition of Done

- Migration 021 applied in Supabase; execution columns + partial index verified.
- `POST /api/v1/ingest/event` returns 200 and runs the pipeline; 401 without a token; 422 on a bad event.
- `GET /playbooks/approvals?pending_execution=true&action_type=block_ip` returns only approved, not-yet-executed block actions.
- `POST /playbooks/approvals/{id}/execution` flips `execution_status`, writes an audit row, and 409s on repeat.
- All three commits made locally. **Not** pushed to `space`/`origin` yet — deploy happens deliberately later (per `DEPLOY.md`) once Phase 2/3 are ready to test end-to-end.

## What comes next (not in this plan)

- **Phase 2 — `tb-collector`** (new `collector/` package): source-adapter interface + SSH brute-force `auth.log` adapter + normalizer + emitter. Strict TDD on the parser and normalizer.
- **Phase 3 — `tb-executor`**: poll loop + IP safety guard (strict TDD) + `iptables` + reporting via the Task 3 endpoint.
- **Phase 4 — live validation**: `hydra` from the attacker box against Kali, end to end.
