DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_key') THEN
    CREATE TYPE public.agent_key AS ENUM (
      'triage',           -- severity + MITRE ATT&CK mapping
      'investigation',    -- event correlation + attack chains
      'response',         -- auto-remediation + playbooks
      'threat_intel',     -- IP reputation + IOC enrichment
      'forensics',        -- timeline reconstruction
      'compliance',       -- GDPR/HIPAA/PCI-DSS reports
      'hunt'              -- proactive threat hunting
    );
  END IF;
END$$;

COMMENT ON TYPE public.agent_key IS
  'The 7 specialized AI agent types in ThreatBrain.';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_status') THEN
    CREATE TYPE public.agent_status AS ENUM (
      'active',     -- running normally
      'paused',     -- temporarily not processing (user-disabled)
      'disabled',   -- plan-gated or admin-disabled
      'error'       -- last run failed; needs attention
    );
  END IF;
END$$;

COMMENT ON TYPE public.agent_status IS
  'Operational status of an agent.';


CREATE TABLE IF NOT EXISTS public.agents (
  id                 UUID                  PRIMARY KEY
                                           DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope.
  -- NULL allowed for global "template" agents (future feature: shared base configs).
  organization_id    UUID                  REFERENCES public.organizations(id)
                                           ON DELETE CASCADE,

  -- Which of the 7 agent types this is
  agent_key          public.agent_key      NOT NULL,

  -- Display
  name               TEXT                  NOT NULL,
  description        TEXT,
  icon               TEXT,                              -- emoji or icon identifier
  color              TEXT,                              -- hex color for UI

  -- Operational
  status             public.agent_status   NOT NULL DEFAULT 'active',
  enabled            BOOLEAN               NOT NULL DEFAULT TRUE,

  -- LLM configuration
  model              TEXT                  NOT NULL DEFAULT 'llama-3.3-70b-versatile',
  temperature        NUMERIC(3,2)          NOT NULL DEFAULT 0.20,
  max_tokens         INTEGER               NOT NULL DEFAULT 4096,

  -- Instructions
  system_prompt      TEXT                  NOT NULL DEFAULT '',

  -- Which tools this agent can call (free-form JSONB list)
  -- e.g., ["abuseipdb_lookup", "virustotal_lookup", "supabase_query"]
  tools              JSONB                 NOT NULL DEFAULT '[]'::jsonb,

  -- Agent-specific tunables (each agent reads its own keys)
  config             JSONB                 NOT NULL DEFAULT '{}'::jsonb,

  -- Versioning: bumped each time the system_prompt or config changes
  version            TEXT                  NOT NULL DEFAULT '1.0.0',

  -- Cached performance metrics (kept fresh by agent_runs triggers in migration 009)
  total_runs         BIGINT                NOT NULL DEFAULT 0,
  successful_runs    BIGINT                NOT NULL DEFAULT 0,
  failed_runs        BIGINT                NOT NULL DEFAULT 0,
  avg_latency_ms     INTEGER               NOT NULL DEFAULT 0,
  last_run_at        TIMESTAMPTZ,
  last_error         TEXT,

  -- Standard timestamps
  created_at         TIMESTAMPTZ           NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ           NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT agents_name_length
    CHECK (char_length(name) BETWEEN 1 AND 120),
  CONSTRAINT agents_temperature_range
    CHECK (temperature >= 0 AND temperature <= 2),
  CONSTRAINT agents_max_tokens_range
    CHECK (max_tokens BETWEEN 1 AND 32768),
  CONSTRAINT agents_runs_nonneg
    CHECK (total_runs >= 0 AND successful_runs >= 0 AND failed_runs >= 0),
  CONSTRAINT agents_latency_nonneg
    CHECK (avg_latency_ms >= 0)
);

COMMENT ON TABLE  public.agents                 IS 'AI agents configured per organization.';
COMMENT ON COLUMN public.agents.id              IS 'UUID primary key.';
COMMENT ON COLUMN public.agents.organization_id IS 'Owning organization (NULL = global template).';
COMMENT ON COLUMN public.agents.agent_key       IS 'Which of the 7 agent types this is.';
COMMENT ON COLUMN public.agents.name            IS 'Display name shown in UI.';
COMMENT ON COLUMN public.agents.description     IS 'What this agent does.';
COMMENT ON COLUMN public.agents.icon            IS 'Emoji or icon identifier for UI.';
COMMENT ON COLUMN public.agents.color           IS 'Hex color used in UI theming.';
COMMENT ON COLUMN public.agents.status          IS 'Operational status.';
COMMENT ON COLUMN public.agents.enabled         IS 'Master on/off toggle.';
COMMENT ON COLUMN public.agents.model           IS 'Groq/LLM model name.';
COMMENT ON COLUMN public.agents.temperature     IS 'LLM temperature (0–2).';
COMMENT ON COLUMN public.agents.max_tokens      IS 'LLM max output tokens.';
COMMENT ON COLUMN public.agents.system_prompt   IS 'Instructions provided to the LLM at the start of every run.';
COMMENT ON COLUMN public.agents.tools           IS 'List of tools this agent is allowed to call.';
COMMENT ON COLUMN public.agents.config          IS 'Agent-specific tunables.';
COMMENT ON COLUMN public.agents.version         IS 'Semver-style version of this agent''s configuration.';
COMMENT ON COLUMN public.agents.total_runs      IS 'Cached count of total runs.';
COMMENT ON COLUMN public.agents.successful_runs IS 'Cached count of successful runs.';
COMMENT ON COLUMN public.agents.failed_runs     IS 'Cached count of failed runs.';
COMMENT ON COLUMN public.agents.avg_latency_ms  IS 'Cached rolling average latency in milliseconds.';
COMMENT ON COLUMN public.agents.last_run_at     IS 'Timestamp of most recent run.';
COMMENT ON COLUMN public.agents.last_error      IS 'Most recent error message (debugging aid).';


-- Exactly one row per (organization_id, agent_key)
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_org_key_unique
  ON public.agents(organization_id, agent_key);

-- Listing all agents for an org (dashboard "agents grid")
CREATE INDEX IF NOT EXISTS idx_agents_organization_id
  ON public.agents(organization_id);

-- Filter by status (e.g., "show me all errored agents")
CREATE INDEX IF NOT EXISTS idx_agents_status
  ON public.agents(organization_id, status);

-- Quick lookup of a single agent by its key
CREATE INDEX IF NOT EXISTS idx_agents_agent_key
  ON public.agents(agent_key);


DROP TRIGGER IF EXISTS set_agents_updated_at ON public.agents;

CREATE TRIGGER set_agents_updated_at
  BEFORE UPDATE ON public.agents
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.seed_default_agents_for_org(p_org_id UUID)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.agents (
    organization_id, agent_key, name, description, icon, color,
    model, temperature, max_tokens, system_prompt, tools, config
  ) VALUES
    (p_org_id, 'triage',         'Triage Agent',         'Classifies severity and maps every event to MITRE ATT&CK tactics and techniques.',
     '🚨', '#ef4444',
     'llama-3.3-70b-versatile', 0.15, 4096,
     'You are the Triage Agent in ThreatBrain. Your job is to classify incoming security events: assign a severity, map to MITRE ATT&CK tactics and techniques, and decide whether to promote the event to a threat. Be precise, evidence-driven, and conservative with high-severity classifications.',
     '["mitre_attck_lookup", "supabase_query"]'::jsonb,
     '{"severity_threshold": "low", "auto_promote": true}'::jsonb),

    (p_org_id, 'investigation',  'Investigation Agent',  'Correlates events across time and assets to reconstruct attack chains.',
     '🔬', '#3b82f6',
     'llama-3.3-70b-versatile', 0.20, 4096,
     'You are the Investigation Agent. Given a set of threats, identify causal links and group them into incidents that tell a single attack story. Reconstruct the kill chain in MITRE tactic order.',
     '["supabase_query", "graph_search"]'::jsonb,
     '{"correlation_window_minutes": 60}'::jsonb),

    (p_org_id, 'response',       'Response Agent',       'Executes auto-remediation playbooks (block IPs, isolate hosts, revoke sessions).',
     '⚡', '#f59e0b',
     'llama-3.3-70b-versatile', 0.10, 2048,
     'You are the Response Agent. Select and execute the safest, highest-impact remediation playbook for a given threat or incident. Prefer reversible actions. Never act on low-confidence threats without human approval.',
     '["n8n_webhook", "supabase_query"]'::jsonb,
     '{"require_human_approval_above_severity": "high", "auto_execute_below_severity": "medium"}'::jsonb),

    (p_org_id, 'threat_intel',   'Threat Intel Agent',   'Enriches IOCs via AbuseIPDB, VirusTotal, Shodan, and AlienVault OTX.',
     '🌐', '#06b6d4',
     'llama-3.3-70b-versatile', 0.20, 4096,
     'You are the Threat Intel Agent. For each IOC (IP, hash, domain, URL), query external feeds and synthesize a concise reputation summary. Flag known-bad indicators with high confidence.',
     '["abuseipdb_lookup", "virustotal_lookup", "shodan_lookup", "otx_lookup"]'::jsonb,
     '{"cache_ttl_minutes": 60}'::jsonb),

    (p_org_id, 'forensics',      'Forensics Agent',      'Builds detailed incident timelines and root-cause analysis.',
     '🕵️', '#8b5cf6',
     'llama-3.3-70b-versatile', 0.20, 6144,
     'You are the Forensics Agent. Given an incident, reconstruct a precise chronological timeline of every relevant event and produce a root-cause narrative suitable for an executive incident report.',
     '["supabase_query", "timeline_builder"]'::jsonb,
     '{"timeline_max_events": 200}'::jsonb),

    (p_org_id, 'compliance',     'Compliance Agent',     'Generates audit-ready GDPR, HIPAA, and PCI-DSS reports.',
     '📋', '#10b981',
     'llama-3.3-70b-versatile', 0.10, 8192,
     'You are the Compliance Agent. Produce audit-ready compliance reports (GDPR, HIPAA, PCI-DSS) summarizing incidents, controls, and notifications within the requested period. Be factual and citation-rich.',
     '["supabase_query", "pdf_builder"]'::jsonb,
     '{"default_frameworks": ["gdpr", "hipaa", "pci_dss"]}'::jsonb),

    (p_org_id, 'hunt',           'Hunt Agent',           'Proactively hunts for threats using AI-generated hypotheses.',
     '🎯', '#ec4899',
     'llama-3.3-70b-versatile', 0.40, 4096,
     'You are the Hunt Agent. Generate plausible attack hypotheses based on recent activity and run targeted searches against historical telemetry to surface threats other agents may have missed.',
     '["supabase_query", "mitre_attck_lookup"]'::jsonb,
     '{"hypotheses_per_run": 3, "lookback_hours": 168}'::jsonb)

  ON CONFLICT (organization_id, agent_key) DO NOTHING;
END;
$$;

COMMENT ON FUNCTION public.seed_default_agents_for_org(UUID) IS
  'Seeds the 7 default ThreatBrain agents for the given organization.';


CREATE OR REPLACE FUNCTION public.handle_new_organization()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  PERFORM public.seed_default_agents_for_org(NEW.id);
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.handle_new_organization() IS
  'Trigger function that seeds the 7 default agents whenever a new organization is created.';

DROP TRIGGER IF EXISTS on_organization_created ON public.organizations;

CREATE TRIGGER on_organization_created
  AFTER INSERT ON public.organizations
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_organization();


DO $$
DECLARE
  org_record RECORD;
BEGIN
  FOR org_record IN SELECT id FROM public.organizations LOOP
    PERFORM public.seed_default_agents_for_org(org_record.id);
  END LOOP;
END$$;


ALTER TABLE public.agents ENABLE ROW LEVEL SECURITY;
