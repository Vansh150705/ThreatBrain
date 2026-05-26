DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'actor_type') THEN
    CREATE TYPE public.actor_type AS ENUM (
      'user',       -- human user action
      'agent',      -- AI agent action
      'system',     -- internal system / cron / scheduled
      'api',        -- API call (programmatic)
      'webhook',    -- external webhook trigger
      'anonymous'   -- pre-auth events (failed logins, signup attempts)
    );
  END IF;
END$$;

COMMENT ON TYPE public.actor_type IS
  'Type of actor that performed an audited action.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'audit_status') THEN
    CREATE TYPE public.audit_status AS ENUM (
      'success',
      'failure',
      'partial',
      'pending'
    );
  END IF;
END$$;

COMMENT ON TYPE public.audit_status IS
  'Outcome of an audited action.';


CREATE TABLE IF NOT EXISTS public.audit_logs (
  id               UUID                 PRIMARY KEY
                                        DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope (NULL allowed for system-level events pre-org)
  organization_id  UUID                 REFERENCES public.organizations(id)
                                        ON DELETE CASCADE,

  -- Human-friendly short reference (e.g., "ALG-A3F2B9")
  short_id         TEXT                 NOT NULL
                                        DEFAULT public.generate_short_id('ALG'),

  -- Actor (who did it)
  actor_type       public.actor_type    NOT NULL,
  actor_id         UUID,                              -- FK to users.id or agents.id (polymorphic, no constraint)
  actor_email      TEXT,                              -- cached for display
  actor_name       TEXT,                              -- cached for display

  -- Action (what they did) — namespaced verb, e.g.:
  --   "auth.login_success"
  --   "threat.created"
  --   "threat.assigned"
  --   "incident.status_changed"
  --   "playbook.executed"
  --   "agent.run_completed"
  --   "user.role_changed"
  --   "organization.settings_updated"
  action           TEXT                 NOT NULL,

  -- Target (what was acted upon)
  target_type      TEXT,                              -- e.g., "threats", "incidents", "users"
  target_id        UUID,                              -- UUID of the target row
  target_short_id  TEXT,                              -- cached short_id for display
  target_name      TEXT,                              -- cached display name

  -- Classification
  severity         public.severity_level NOT NULL DEFAULT 'info',
  status           public.audit_status   NOT NULL DEFAULT 'success',

  -- State snapshots
  before_state     JSONB                NOT NULL DEFAULT '{}'::jsonb,
  after_state      JSONB                NOT NULL DEFAULT '{}'::jsonb,
  changes          JSONB                NOT NULL DEFAULT '{}'::jsonb,

  -- Free-form explanation
  reason           TEXT,

  -- Request context (security forensics)
  ip_address       INET,
  user_agent       TEXT,
  session_id       TEXT,

  -- Groups related entries from one logical operation
  -- (e.g., one playbook execution might emit 5 audit rows; they all share correlation_id)
  correlation_id   UUID,

  -- Free-form additional context
  metadata         JSONB                NOT NULL DEFAULT '{}'::jsonb,

  -- Free-form labels (e.g., ['gdpr','data-access','sensitive'])
  tags             TEXT[]               NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Append-only: no updated_at column
  created_at       TIMESTAMPTZ          NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT audit_logs_action_length
    CHECK (char_length(action) BETWEEN 1 AND 200),
  CONSTRAINT audit_logs_target_type_length
    CHECK (target_type IS NULL OR char_length(target_type) BETWEEN 1 AND 100),
  CONSTRAINT audit_logs_user_agent_length
    CHECK (user_agent IS NULL OR char_length(user_agent) <= 2000)
);

COMMENT ON TABLE  public.audit_logs                 IS 'Append-only audit trail of every meaningful action in ThreatBrain.';
COMMENT ON COLUMN public.audit_logs.id              IS 'UUID primary key.';
COMMENT ON COLUMN public.audit_logs.organization_id IS 'Owning organization (NULL for system pre-org events).';
COMMENT ON COLUMN public.audit_logs.short_id        IS 'Human-friendly short reference.';
COMMENT ON COLUMN public.audit_logs.actor_type      IS 'Type of actor (user, agent, system, api, webhook, anonymous).';
COMMENT ON COLUMN public.audit_logs.actor_id        IS 'UUID of the acting user/agent (polymorphic, no FK).';
COMMENT ON COLUMN public.audit_logs.actor_email     IS 'Cached actor email for display.';
COMMENT ON COLUMN public.audit_logs.actor_name      IS 'Cached actor display name.';
COMMENT ON COLUMN public.audit_logs.action          IS 'Namespaced verb describing the action (e.g., "threat.created").';
COMMENT ON COLUMN public.audit_logs.target_type     IS 'Entity type acted upon (e.g., "threats", "incidents").';
COMMENT ON COLUMN public.audit_logs.target_id       IS 'UUID of the target entity.';
COMMENT ON COLUMN public.audit_logs.target_short_id IS 'Cached short_id of the target for display.';
COMMENT ON COLUMN public.audit_logs.target_name     IS 'Cached name of the target for display.';
COMMENT ON COLUMN public.audit_logs.severity        IS 'Severity classification of the action.';
COMMENT ON COLUMN public.audit_logs.status          IS 'Outcome: success, failure, partial, pending.';
COMMENT ON COLUMN public.audit_logs.before_state    IS 'JSONB snapshot of the target before the action.';
COMMENT ON COLUMN public.audit_logs.after_state     IS 'JSONB snapshot of the target after the action.';
COMMENT ON COLUMN public.audit_logs.changes         IS 'JSONB diff between before and after.';
COMMENT ON COLUMN public.audit_logs.reason          IS 'Human or AI explanation of why the action was taken.';
COMMENT ON COLUMN public.audit_logs.ip_address      IS 'Client IP address (INET).';
COMMENT ON COLUMN public.audit_logs.user_agent      IS 'Browser/SDK user agent string.';
COMMENT ON COLUMN public.audit_logs.session_id      IS 'Auth session reference for correlation.';
COMMENT ON COLUMN public.audit_logs.correlation_id  IS 'Groups related audit entries from one logical operation.';
COMMENT ON COLUMN public.audit_logs.metadata        IS 'Free-form additional context.';
COMMENT ON COLUMN public.audit_logs.tags            IS 'Free-form labels.';


-- Main feed (most recent first per org)
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created_at
  ON public.audit_logs(organization_id, created_at DESC);

-- Filter by actor (e.g., "show me everything user X did")
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id
  ON public.audit_logs(actor_id, created_at DESC)
  WHERE actor_id IS NOT NULL;

-- Filter by actor type (e.g., "all agent actions")
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_type
  ON public.audit_logs(organization_id, actor_type, created_at DESC);

-- Filter by action (e.g., "all threat.assigned actions")
CREATE INDEX IF NOT EXISTS idx_audit_logs_action
  ON public.audit_logs(organization_id, action, created_at DESC);

-- Find audit entries for a specific target entity
CREATE INDEX IF NOT EXISTS idx_audit_logs_target
  ON public.audit_logs(target_type, target_id, created_at DESC)
  WHERE target_id IS NOT NULL;

-- Severity-filtered feeds
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity
  ON public.audit_logs(organization_id, severity, created_at DESC);

-- Status-filtered feeds ("show me all failures")
CREATE INDEX IF NOT EXISTS idx_audit_logs_status
  ON public.audit_logs(organization_id, status, created_at DESC);

-- Correlation grouping (find all entries from one logical operation)
CREATE INDEX IF NOT EXISTS idx_audit_logs_correlation_id
  ON public.audit_logs(correlation_id)
  WHERE correlation_id IS NOT NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_audit_logs_short_id
  ON public.audit_logs(short_id);

-- IP-based forensics
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address
  ON public.audit_logs(ip_address)
  WHERE ip_address IS NOT NULL;

-- Session forensics
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id
  ON public.audit_logs(session_id)
  WHERE session_id IS NOT NULL;

-- Tag search (compliance scoping: GDPR, PCI-DSS, etc.)
CREATE INDEX IF NOT EXISTS idx_audit_logs_tags
  ON public.audit_logs USING GIN(tags);

-- Changes/metadata drill-down
CREATE INDEX IF NOT EXISTS idx_audit_logs_changes
  ON public.audit_logs USING GIN(changes);

CREATE INDEX IF NOT EXISTS idx_audit_logs_metadata
  ON public.audit_logs USING GIN(metadata);


CREATE OR REPLACE FUNCTION public.prevent_audit_log_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  -- Escape hatch: superuser maintenance can opt-in to mutation
  IF current_setting('audit_logs.allow_mutation', TRUE) = 'on' THEN
    RETURN COALESCE(NEW, OLD);
  END IF;

  RAISE EXCEPTION 'audit_logs is append-only; % operations are not permitted', TG_OP
    USING HINT = 'Audit log entries are immutable by design for compliance.';
END;
$$;

COMMENT ON FUNCTION public.prevent_audit_log_mutation() IS
  'Blocks UPDATE and DELETE on audit_logs to keep the table append-only.';

DROP TRIGGER IF EXISTS prevent_audit_logs_update ON public.audit_logs;
DROP TRIGGER IF EXISTS prevent_audit_logs_delete ON public.audit_logs;

CREATE TRIGGER prevent_audit_logs_update
  BEFORE UPDATE ON public.audit_logs
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_audit_log_mutation();

CREATE TRIGGER prevent_audit_logs_delete
  BEFORE DELETE ON public.audit_logs
  FOR EACH ROW
  EXECUTE FUNCTION public.prevent_audit_log_mutation();


CREATE OR REPLACE FUNCTION public.log_audit_event(
  p_organization_id  UUID,
  p_actor_type       public.actor_type,
  p_action           TEXT,
  p_actor_id         UUID                = NULL,
  p_actor_email      TEXT                = NULL,
  p_actor_name       TEXT                = NULL,
  p_target_type      TEXT                = NULL,
  p_target_id        UUID                = NULL,
  p_target_short_id  TEXT                = NULL,
  p_target_name      TEXT                = NULL,
  p_severity         public.severity_level = 'info',
  p_status           public.audit_status   = 'success',
  p_before_state     JSONB               = '{}'::jsonb,
  p_after_state      JSONB               = '{}'::jsonb,
  p_changes          JSONB               = '{}'::jsonb,
  p_reason           TEXT                = NULL,
  p_ip_address       INET                = NULL,
  p_user_agent       TEXT                = NULL,
  p_session_id       TEXT                = NULL,
  p_correlation_id   UUID                = NULL,
  p_metadata         JSONB               = '{}'::jsonb,
  p_tags             TEXT[]              = ARRAY[]::TEXT[]
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  new_id UUID;
BEGIN
  INSERT INTO public.audit_logs (
    organization_id, actor_type, actor_id, actor_email, actor_name,
    action, target_type, target_id, target_short_id, target_name,
    severity, status, before_state, after_state, changes,
    reason, ip_address, user_agent, session_id, correlation_id,
    metadata, tags
  ) VALUES (
    p_organization_id, p_actor_type, p_actor_id, p_actor_email, p_actor_name,
    p_action, p_target_type, p_target_id, p_target_short_id, p_target_name,
    p_severity, p_status, p_before_state, p_after_state, p_changes,
    p_reason, p_ip_address, p_user_agent, p_session_id, p_correlation_id,
    p_metadata, p_tags
  )
  RETURNING id INTO new_id;

  RETURN new_id;
END;
$$;

COMMENT ON FUNCTION public.log_audit_event IS
  'Convenience wrapper for inserting an audit log entry.';


ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
