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
