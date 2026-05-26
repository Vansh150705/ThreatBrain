DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'run_trigger_type') THEN
    CREATE TYPE public.run_trigger_type AS ENUM (
      'event',       -- triggered by a new event (e.g., Triage on event ingest)
      'threat',      -- triggered by a new/updated threat (e.g., Threat Intel enrichment)
      'incident',    -- triggered by an incident update (e.g., Forensics timeline rebuild)
      'manual',      -- analyst clicked "run agent" in the UI
      'scheduled',   -- cron / periodic (e.g., Hunt Agent every hour)
      'webhook',     -- external trigger (N8N, API call)
      'chained'      -- triggered by another agent's output
    );
  END IF;
END$$;

COMMENT ON TYPE public.run_trigger_type IS
  'What initiated an agent run.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'run_status') THEN
    CREATE TYPE public.run_status AS ENUM (
      'pending',     -- queued, not yet started
      'running',     -- in progress
      'completed',   -- finished successfully
      'failed',      -- errored out
      'timeout',     -- exceeded max execution time
      'cancelled'    -- aborted by user or system
    );
  END IF;
END$$;

COMMENT ON TYPE public.run_status IS
  'Lifecycle status of an agent run.';


CREATE TABLE IF NOT EXISTS public.agent_runs (
  id                UUID                    PRIMARY KEY
                                            DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id   UUID                    NOT NULL
                                            REFERENCES public.organizations(id)
                                            ON DELETE CASCADE,

  -- The agent that ran
  agent_id          UUID                    NOT NULL
                                            REFERENCES public.agents(id)
                                            ON DELETE CASCADE,

  -- Denormalized agent_key for cheap filtering (e.g., "all triage runs today")
  -- Saves a join when generating dashboard metrics.
  agent_key         public.agent_key        NOT NULL,

  -- Human-friendly short reference (e.g., "RUN-A3F2B9")
  short_id          TEXT                    NOT NULL
                                            DEFAULT public.generate_short_id('RUN'),

  -- What triggered this run
  trigger_type      public.run_trigger_type NOT NULL,

  -- Polymorphic FK: ID of the triggering entity
  -- (event_id / threat_id / incident_id / NULL for manual/scheduled)
  trigger_id        UUID,

  -- Inputs and outputs (free-form JSONB)
  -- input  = what the agent received (raw event, threat context, user prompt, etc.)
  -- output = what the agent produced (severity verdict, enrichment, playbook result, etc.)
  input             JSONB                   NOT NULL DEFAULT '{}'::jsonb,
  output            JSONB                   NOT NULL DEFAULT '{}'::jsonb,

  -- LLM chain-of-thought / scratchpad (raw reasoning text)
  reasoning         TEXT,

  -- Array of tool invocations during this run
  -- Each entry: {tool: "abuseipdb_lookup", input: {...}, output: {...}, latency_ms: 123}
  tool_calls        JSONB                   NOT NULL DEFAULT '[]'::jsonb,

  -- Run lifecycle
  status            public.run_status       NOT NULL DEFAULT 'pending',
  error_message     TEXT,
  error_code        TEXT,

  -- Token usage (Groq returns these in response.usage)
  model             TEXT,
  prompt_tokens     INTEGER                 NOT NULL DEFAULT 0,
  completion_tokens INTEGER                 NOT NULL DEFAULT 0,
  total_tokens      INTEGER                 NOT NULL DEFAULT 0,

  -- Performance
  latency_ms        INTEGER,                -- total wall-clock time for the run

  -- Timestamps
  started_at        TIMESTAMPTZ,
  completed_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ             NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ             NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT agent_runs_tokens_nonneg
    CHECK (prompt_tokens >= 0 AND completion_tokens >= 0 AND total_tokens >= 0),
  CONSTRAINT agent_runs_latency_nonneg
    CHECK (latency_ms IS NULL OR latency_ms >= 0),
  CONSTRAINT agent_runs_completed_after_started
    CHECK (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at)
);

COMMENT ON TABLE  public.agent_runs                   IS 'Execution history of every agent invocation.';
COMMENT ON COLUMN public.agent_runs.id                IS 'UUID primary key.';
COMMENT ON COLUMN public.agent_runs.organization_id   IS 'Owning organization.';
COMMENT ON COLUMN public.agent_runs.agent_id          IS 'The agent that ran.';
COMMENT ON COLUMN public.agent_runs.agent_key         IS 'Denormalized agent type for cheap filtering.';
COMMENT ON COLUMN public.agent_runs.short_id          IS 'Human-friendly short reference (e.g., RUN-A3F2B9).';
COMMENT ON COLUMN public.agent_runs.trigger_type      IS 'What caused this run (event, threat, manual, scheduled, etc.).';
COMMENT ON COLUMN public.agent_runs.trigger_id        IS 'Polymorphic FK to the triggering entity (event/threat/incident UUID).';
COMMENT ON COLUMN public.agent_runs.input             IS 'Free-form JSONB: what the agent received.';
COMMENT ON COLUMN public.agent_runs.output            IS 'Free-form JSONB: what the agent produced.';
COMMENT ON COLUMN public.agent_runs.reasoning         IS 'LLM chain-of-thought / scratchpad text.';
COMMENT ON COLUMN public.agent_runs.tool_calls        IS 'Array of tool invocations made during this run.';
COMMENT ON COLUMN public.agent_runs.status            IS 'Lifecycle status (pending, running, completed, failed, etc.).';
COMMENT ON COLUMN public.agent_runs.error_message     IS 'Human-readable error message if status=failed/timeout.';
COMMENT ON COLUMN public.agent_runs.error_code        IS 'Machine-readable error code for grouping (e.g., RATE_LIMIT, TOOL_TIMEOUT).';
COMMENT ON COLUMN public.agent_runs.model             IS 'Which LLM model executed this run.';
COMMENT ON COLUMN public.agent_runs.prompt_tokens     IS 'Input token count.';
COMMENT ON COLUMN public.agent_runs.completion_tokens IS 'Output token count.';
COMMENT ON COLUMN public.agent_runs.total_tokens      IS 'Total tokens (prompt + completion).';
COMMENT ON COLUMN public.agent_runs.latency_ms        IS 'Total wall-clock latency in milliseconds.';
COMMENT ON COLUMN public.agent_runs.started_at        IS 'When execution began.';
COMMENT ON COLUMN public.agent_runs.completed_at      IS 'When execution finished (success or failure).';


-- Main activity feed (recent runs per org)
CREATE INDEX IF NOT EXISTS idx_agent_runs_org_created_at
  ON public.agent_runs(organization_id, created_at DESC);

-- Per-agent run history
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent_id
  ON public.agent_runs(agent_id, created_at DESC);

-- Per-agent-type analytics (e.g., all Triage runs)
CREATE INDEX IF NOT EXISTS idx_agent_runs_agent_key
  ON public.agent_runs(organization_id, agent_key, created_at DESC);

-- Status filtering (e.g., "show me failed runs")
CREATE INDEX IF NOT EXISTS idx_agent_runs_status
  ON public.agent_runs(organization_id, status, created_at DESC);

-- Trigger-source lookups (find all runs triggered by this threat)
CREATE INDEX IF NOT EXISTS idx_agent_runs_trigger
  ON public.agent_runs(trigger_type, trigger_id)
  WHERE trigger_id IS NOT NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_agent_runs_short_id
  ON public.agent_runs(short_id);

-- Pending/running queue
CREATE INDEX IF NOT EXISTS idx_agent_runs_active
  ON public.agent_runs(organization_id, created_at ASC)
  WHERE status IN ('pending', 'running');

-- Tool-call drilldown
CREATE INDEX IF NOT EXISTS idx_agent_runs_tool_calls
  ON public.agent_runs USING GIN(tool_calls);


DROP TRIGGER IF EXISTS set_agent_runs_updated_at ON public.agent_runs;

CREATE TRIGGER set_agent_runs_updated_at
  BEFORE UPDATE ON public.agent_runs
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.update_agent_stats_on_run()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
  is_terminal_now BOOLEAN := NEW.status IN ('completed', 'failed', 'timeout', 'cancelled');
  was_terminal_before BOOLEAN := (OLD.status IS NOT NULL)
                                  AND (OLD.status IN ('completed', 'failed', 'timeout', 'cancelled'));
BEGIN
  -- Only fire when transitioning INTO a terminal state
  IF is_terminal_now AND NOT was_terminal_before THEN

    UPDATE public.agents
    SET
      total_runs      = total_runs + 1,
      successful_runs = successful_runs + CASE WHEN NEW.status = 'completed' THEN 1 ELSE 0 END,
      failed_runs     = failed_runs     + CASE WHEN NEW.status IN ('failed', 'timeout') THEN 1 ELSE 0 END,
      avg_latency_ms  = CASE
                          WHEN NEW.latency_ms IS NULL THEN avg_latency_ms
                          WHEN total_runs = 0 THEN NEW.latency_ms
                          ELSE GREATEST(0, ROUND(avg_latency_ms * 0.9 + NEW.latency_ms * 0.1))::INTEGER
                        END,
      last_run_at     = COALESCE(NEW.completed_at, NOW()),
      last_error      = CASE
                          WHEN NEW.status IN ('failed', 'timeout') THEN NEW.error_message
                          ELSE NULL
                        END
    WHERE id = NEW.agent_id;

  END IF;

  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.update_agent_stats_on_run() IS
  'Keeps the agents table aggregate stats fresh whenever an agent_run completes.';

DROP TRIGGER IF EXISTS update_agent_stats_after_run ON public.agent_runs;

CREATE TRIGGER update_agent_stats_after_run
  AFTER UPDATE OF status ON public.agent_runs
  FOR EACH ROW
  EXECUTE FUNCTION public.update_agent_stats_on_run();

-- Also fire on direct INSERT of a terminal-state row
-- (e.g., a synchronous run that's "completed" in one shot)
CREATE OR REPLACE FUNCTION public.update_agent_stats_on_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status IN ('completed', 'failed', 'timeout', 'cancelled') THEN
    UPDATE public.agents
    SET
      total_runs      = total_runs + 1,
      successful_runs = successful_runs + CASE WHEN NEW.status = 'completed' THEN 1 ELSE 0 END,
      failed_runs     = failed_runs     + CASE WHEN NEW.status IN ('failed', 'timeout') THEN 1 ELSE 0 END,
      avg_latency_ms  = CASE
                          WHEN NEW.latency_ms IS NULL THEN avg_latency_ms
                          WHEN total_runs = 0 THEN NEW.latency_ms
                          ELSE GREATEST(0, ROUND(avg_latency_ms * 0.9 + NEW.latency_ms * 0.1))::INTEGER
                        END,
      last_run_at     = COALESCE(NEW.completed_at, NOW()),
      last_error      = CASE
                          WHEN NEW.status IN ('failed', 'timeout') THEN NEW.error_message
                          ELSE NULL
                        END
    WHERE id = NEW.agent_id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS update_agent_stats_after_insert ON public.agent_runs;

CREATE TRIGGER update_agent_stats_after_insert
  AFTER INSERT ON public.agent_runs
  FOR EACH ROW
  EXECUTE FUNCTION public.update_agent_stats_on_insert();


ALTER TABLE public.agent_runs ENABLE ROW LEVEL SECURITY;
