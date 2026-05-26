DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'playbook_category') THEN
    CREATE TYPE public.playbook_category AS ENUM (
      'containment',     -- stop the bleeding (block IP, isolate host)
      'eradication',     -- remove the threat (kill malware, revoke creds)
      'recovery',        -- restore service (re-image host, restore data)
      'investigation',   -- gather more info before acting
      'notification',    -- alert humans (page on-call, post to Slack)
      'enrichment'       -- enrich the threat with more context
    );
  END IF;
END$$;

COMMENT ON TYPE public.playbook_category IS
  'NIST-aligned response phase category.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'playbook_status') THEN
    CREATE TYPE public.playbook_status AS ENUM (
      'draft',
      'active',
      'deprecated',
      'disabled'
    );
  END IF;
END$$;

COMMENT ON TYPE public.playbook_status IS
  'Lifecycle status of a playbook.';


CREATE TABLE IF NOT EXISTS public.playbooks (
  id                     UUID                       PRIMARY KEY
                                                    DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope (NULL = global template)
  organization_id        UUID                       REFERENCES public.organizations(id)
                                                    ON DELETE CASCADE,

  -- Human-friendly short reference (e.g., "PBK-A3F2B9")
  short_id               TEXT                       NOT NULL
                                                    DEFAULT public.generate_short_id('PBK'),

  -- Display
  name                   TEXT                       NOT NULL,
  description            TEXT,

  -- Classification
  category               public.playbook_category   NOT NULL,
  status                 public.playbook_status     NOT NULL DEFAULT 'active',
  version                TEXT                       NOT NULL DEFAULT '1.0.0',
  enabled                BOOLEAN                    NOT NULL DEFAULT TRUE,

  -- Execution policy
  auto_execute           BOOLEAN                    NOT NULL DEFAULT FALSE,
  approval_required      BOOLEAN                    NOT NULL DEFAULT TRUE,

  -- Trigger gating
  min_confidence         SMALLINT                   NOT NULL DEFAULT 70,
  max_severity_auto      public.severity_level      NOT NULL DEFAULT 'medium',

  -- Matching conditions (free-form JSONB filter expression)
  -- e.g., {"event_types": ["network.brute_force"], "min_severity": "high"}
  trigger_conditions     JSONB                      NOT NULL DEFAULT '{}'::jsonb,

  -- The ordered list of steps (each step is an action object)
  -- e.g., [
  --   {"name": "block_ip", "tool": "firewall_api", "params": {...}},
  --   {"name": "notify_soc", "tool": "slack_webhook", "params": {...}}
  -- ]
  steps                  JSONB                      NOT NULL DEFAULT '[]'::jsonb,

  -- Integrations this playbook needs available
  required_integrations  TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- MITRE techniques this playbook responds to
  mitre_techniques       TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Free-form labels
  tags                   TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Authorship
  created_by             UUID                       REFERENCES public.users(id)
                                                    ON DELETE SET NULL,

  -- Cached performance metrics (kept fresh as playbook runs are recorded)
  total_executions       BIGINT                     NOT NULL DEFAULT 0,
  successful_executions  BIGINT                     NOT NULL DEFAULT 0,
  failed_executions      BIGINT                     NOT NULL DEFAULT 0,
  avg_duration_ms        INTEGER                    NOT NULL DEFAULT 0,
  last_executed_at       TIMESTAMPTZ,

  -- Soft-delete
  deleted_at             TIMESTAMPTZ,

  -- Standard timestamps
  created_at             TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ                NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT playbooks_name_length
    CHECK (char_length(name) BETWEEN 1 AND 200),
  CONSTRAINT playbooks_min_confidence_range
    CHECK (min_confidence BETWEEN 0 AND 100),
  CONSTRAINT playbooks_executions_nonneg
    CHECK (total_executions >= 0 AND successful_executions >= 0 AND failed_executions >= 0),
  CONSTRAINT playbooks_avg_duration_nonneg
    CHECK (avg_duration_ms >= 0),
  -- A playbook can't be auto_execute = TRUE while also requiring approval
  CONSTRAINT playbooks_auto_vs_approval
    CHECK (NOT (auto_execute = TRUE AND approval_required = TRUE))
);

COMMENT ON TABLE  public.playbooks                       IS 'Reusable automated remediation procedures for the Response Agent.';
COMMENT ON COLUMN public.playbooks.id                    IS 'UUID primary key.';
COMMENT ON COLUMN public.playbooks.organization_id       IS 'Owning organization (NULL = global template).';
COMMENT ON COLUMN public.playbooks.short_id              IS 'Human-friendly short reference.';
COMMENT ON COLUMN public.playbooks.name                  IS 'Display name (e.g., "Block Malicious IP").';
COMMENT ON COLUMN public.playbooks.description           IS 'What this playbook does.';
COMMENT ON COLUMN public.playbooks.category              IS 'NIST IR phase: containment, eradication, recovery, etc.';
COMMENT ON COLUMN public.playbooks.status                IS 'Lifecycle status.';
COMMENT ON COLUMN public.playbooks.version               IS 'Semver-style version string.';
COMMENT ON COLUMN public.playbooks.enabled               IS 'Master on/off toggle.';
COMMENT ON COLUMN public.playbooks.auto_execute          IS 'TRUE = run autonomously; FALSE = require explicit invocation.';
COMMENT ON COLUMN public.playbooks.approval_required     IS 'TRUE = pause for human signoff before executing.';
COMMENT ON COLUMN public.playbooks.min_confidence        IS 'Minimum threat confidence required to trigger this playbook (0–100).';
COMMENT ON COLUMN public.playbooks.max_severity_auto     IS 'Maximum severity at which auto_execute is allowed.';
COMMENT ON COLUMN public.playbooks.trigger_conditions    IS 'JSONB filter describing when this playbook applies.';
COMMENT ON COLUMN public.playbooks.steps                 IS 'Ordered array of step objects (tool + params).';
COMMENT ON COLUMN public.playbooks.required_integrations IS 'Integrations needed (n8n, aws, slack, etc.).';
COMMENT ON COLUMN public.playbooks.mitre_techniques      IS 'MITRE technique IDs this playbook responds to.';
COMMENT ON COLUMN public.playbooks.tags                  IS 'Free-form labels.';
COMMENT ON COLUMN public.playbooks.created_by            IS 'User who authored this playbook.';
COMMENT ON COLUMN public.playbooks.total_executions      IS 'Cached count of total executions.';
COMMENT ON COLUMN public.playbooks.successful_executions IS 'Cached count of successful executions.';
COMMENT ON COLUMN public.playbooks.failed_executions     IS 'Cached count of failed executions.';
COMMENT ON COLUMN public.playbooks.avg_duration_ms       IS 'Cached rolling-average execution time in milliseconds.';
COMMENT ON COLUMN public.playbooks.last_executed_at      IS 'Timestamp of most recent execution.';
COMMENT ON COLUMN public.playbooks.deleted_at            IS 'Soft-delete timestamp.';


-- Unique playbook name per org
CREATE UNIQUE INDEX IF NOT EXISTS idx_playbooks_org_name_unique
  ON public.playbooks(organization_id, lower(name))
  WHERE deleted_at IS NULL;

-- Listing playbooks for an org
CREATE INDEX IF NOT EXISTS idx_playbooks_organization_id
  ON public.playbooks(organization_id)
  WHERE deleted_at IS NULL;

-- Category-filtered listings
CREATE INDEX IF NOT EXISTS idx_playbooks_category
  ON public.playbooks(organization_id, category)
  WHERE deleted_at IS NULL;

-- Active enabled playbooks (the Response Agent's working set)
CREATE INDEX IF NOT EXISTS idx_playbooks_active
  ON public.playbooks(organization_id, category)
  WHERE deleted_at IS NULL
    AND enabled = TRUE
    AND status = 'active';

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_playbooks_short_id
  ON public.playbooks(short_id);

-- MITRE technique search ("find playbooks for T1110")
CREATE INDEX IF NOT EXISTS idx_playbooks_mitre_techniques
  ON public.playbooks USING GIN(mitre_techniques);

-- Tag search
CREATE INDEX IF NOT EXISTS idx_playbooks_tags
  ON public.playbooks USING GIN(tags);

-- Required-integration filter
CREATE INDEX IF NOT EXISTS idx_playbooks_required_integrations
  ON public.playbooks USING GIN(required_integrations);

-- Trigger-condition drill-down
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_conditions
  ON public.playbooks USING GIN(trigger_conditions);


DROP TRIGGER IF EXISTS set_playbooks_updated_at ON public.playbooks;

CREATE TRIGGER set_playbooks_updated_at
  BEFORE UPDATE ON public.playbooks
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.seed_default_playbooks_for_org(p_org_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.playbooks (
    organization_id, name, description, category, auto_execute, approval_required,
    min_confidence, max_severity_auto, trigger_conditions, steps,
    required_integrations, mitre_techniques, tags
  ) VALUES
    -- 1. Block Malicious IP
    (p_org_id,
     'Block Malicious IP',
     'Adds a confirmed-malicious source IP to the perimeter firewall blocklist and notifies the SOC channel.',
     'containment', TRUE, FALSE, 80, 'high',
     '{"ioc_types": ["ipv4","ipv6"], "min_reputation": "malicious"}'::jsonb,
     '[
        {"step": 1, "name": "validate_ioc",       "tool": "supabase_query",  "params": {"check_reputation": true}},
        {"step": 2, "name": "block_at_firewall",  "tool": "n8n_webhook",     "params": {"workflow": "firewall_block_ip"}},
        {"step": 3, "name": "notify_soc_channel", "tool": "discord_webhook", "params": {"channel": "soc-alerts"}}
      ]'::jsonb,
     ARRAY['n8n','discord'], ARRAY['T1190','T1110'], ARRAY['containment','network','automated']),

    -- 2. Isolate Compromised Host
    (p_org_id,
     'Isolate Compromised Host',
     'Removes a compromised endpoint from the network, snapshots it for forensics, and pages the on-call analyst.',
     'containment', FALSE, TRUE, 85, 'medium',
     '{"event_types": ["process.suspicious","malware.detected"], "min_severity": "high"}'::jsonb,
     '[
        {"step": 1, "name": "snapshot_host",       "tool": "n8n_webhook", "params": {"workflow": "edr_snapshot"}},
        {"step": 2, "name": "isolate_network",     "tool": "n8n_webhook", "params": {"workflow": "edr_isolate"}},
        {"step": 3, "name": "revoke_sessions",     "tool": "n8n_webhook", "params": {"workflow": "okta_revoke_sessions"}},
        {"step": 4, "name": "page_on_call",        "tool": "discord_webhook", "params": {"channel": "soc-pager", "mention": "@oncall"}}
      ]'::jsonb,
     ARRAY['n8n','okta','discord'], ARRAY['T1059','T1486'], ARRAY['containment','endpoint','high-impact']),

    -- 3. Quarantine Phishing Email
    (p_org_id,
     'Quarantine Phishing Email',
     'Pulls a phishing email from all inboxes, blocks the sender domain, and notifies affected users.',
     'eradication', TRUE, FALSE, 75, 'high',
     '{"event_types": ["email.phishing"], "min_severity": "medium"}'::jsonb,
     '[
        {"step": 1, "name": "purge_from_inboxes",  "tool": "n8n_webhook", "params": {"workflow": "m365_purge_email"}},
        {"step": 2, "name": "block_sender_domain", "tool": "n8n_webhook", "params": {"workflow": "m365_block_sender"}},
        {"step": 3, "name": "notify_affected",     "tool": "resend_email",  "params": {"template": "phishing_warning"}}
      ]'::jsonb,
     ARRAY['n8n','resend'], ARRAY['T1566'], ARRAY['eradication','email','phishing']),

    -- 4. Disable Compromised User
    (p_org_id,
     'Disable Compromised User',
     'Revokes OAuth tokens, forces a password reset, and disables MFA recovery for a suspected compromised account.',
     'containment', FALSE, TRUE, 90, 'medium',
     '{"event_types": ["authentication.suspicious","credential.theft"], "min_severity": "high"}'::jsonb,
     '[
        {"step": 1, "name": "revoke_oauth_tokens", "tool": "n8n_webhook", "params": {"workflow": "okta_revoke_oauth"}},
        {"step": 2, "name": "force_password_reset","tool": "n8n_webhook", "params": {"workflow": "okta_force_reset"}},
        {"step": 3, "name": "disable_mfa_recovery","tool": "n8n_webhook", "params": {"workflow": "okta_disable_mfa_recovery"}},
        {"step": 4, "name": "notify_admin",        "tool": "discord_webhook", "params": {"channel": "iam-admin"}}
      ]'::jsonb,
     ARRAY['n8n','okta','discord'], ARRAY['T1078','T1110'], ARRAY['containment','identity','iam']),

    -- 5. Critical Threat Notification
    (p_org_id,
     'Critical Threat Notification',
     'Generic high-signal notification playbook: posts the threat to the SOC channel, emails leadership, and creates a tracking ticket.',
     'notification', TRUE, FALSE, 70, 'critical',
     '{"min_severity": "critical"}'::jsonb,
     '[
        {"step": 1, "name": "post_to_soc",       "tool": "discord_webhook", "params": {"channel": "soc-criticals"}},
        {"step": 2, "name": "email_leadership",  "tool": "resend_email",    "params": {"template": "exec_critical_alert"}},
        {"step": 3, "name": "open_incident_ticket","tool": "n8n_webhook",   "params": {"workflow": "jira_create_incident"}}
      ]'::jsonb,
     ARRAY['discord','resend','n8n'], ARRAY[]::TEXT[], ARRAY['notification','critical','executive'])

  ON CONFLICT DO NOTHING;
END;
$$;

COMMENT ON FUNCTION public.seed_default_playbooks_for_org(UUID) IS
  'Seeds 5 default response playbooks for the given organization.';


CREATE OR REPLACE FUNCTION public.handle_new_organization()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  PERFORM public.seed_default_agents_for_org(NEW.id);
  PERFORM public.seed_default_playbooks_for_org(NEW.id);
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.handle_new_organization() IS
  'Trigger function: seeds 7 default agents and 5 default playbooks for every new organization.';

DO $$
DECLARE
  org_record RECORD;
BEGIN
  FOR org_record IN SELECT id FROM public.organizations LOOP
    PERFORM public.seed_default_playbooks_for_org(org_record.id);
  END LOOP;
END$$;

ALTER TABLE public.playbooks ENABLE ROW LEVEL SECURITY;
