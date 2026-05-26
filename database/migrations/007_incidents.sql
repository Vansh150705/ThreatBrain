DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'incident_priority') THEN
    CREATE TYPE public.incident_priority AS ENUM (
      'p1',
      'p2',
      'p3',
      'p4'
    );
  END IF;
END$$;

COMMENT ON TYPE public.incident_priority IS
  'SOC priority levels: P1 (critical) through P4 (low).';


CREATE TABLE IF NOT EXISTS public.incidents (
  id                  UUID                       PRIMARY KEY
                                                 DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id     UUID                       NOT NULL
                                                 REFERENCES public.organizations(id)
                                                 ON DELETE CASCADE,

  -- Human-friendly short reference (e.g., "INC-A3F2B9")
  short_id            TEXT                       NOT NULL
                                                 DEFAULT public.generate_short_id('INC'),

  -- Human-readable
  title               TEXT                       NOT NULL,
  description         TEXT,

  -- Verdict
  severity            public.severity_level      NOT NULL DEFAULT 'medium',
  status              public.status_level        NOT NULL DEFAULT 'open',
  priority            public.incident_priority   NOT NULL DEFAULT 'p3',

  -- Confidence & risk
  confidence          SMALLINT                   NOT NULL DEFAULT 50,
  risk_score          SMALLINT                   NOT NULL DEFAULT 0,

  -- Cached counters (kept fresh by triggers / agents to avoid expensive joins)
  threat_count        INTEGER                    NOT NULL DEFAULT 0,
  asset_count         INTEGER                    NOT NULL DEFAULT 0,

  -- Reconstructed kill chain (ordered MITRE tactic sequence)
  -- e.g., ['TA0001','TA0006','TA0008','TA0010']
  kill_chain          TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- All tactics/techniques across linked threats (deduplicated)
  mitre_tactics       TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],
  mitre_techniques    TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- All assets affected
  affected_asset_ids  UUID[]                     NOT NULL DEFAULT ARRAY[]::UUID[],

  -- All attacker IPs involved
  source_ips          INET[]                     NOT NULL DEFAULT ARRAY[]::INET[],

  -- Attribution: suspected actor, campaign, malware family
  -- e.g., {"actor":"APT29","campaign":"NOBELIUM","family":"Cozy Bear"}
  attribution         JSONB                      NOT NULL DEFAULT '{}'::jsonb,

  -- Forensics Agent timeline reconstruction
  timeline            JSONB                      NOT NULL DEFAULT '[]'::jsonb,

  -- Response Agent action log (executed playbooks, outcomes)
  playbook_runs       JSONB                      NOT NULL DEFAULT '[]'::jsonb,

  -- Investigation Agent reasoning trail
  ai_summary          JSONB                      NOT NULL DEFAULT '{}'::jsonb,

  -- Free-form labels
  tags                TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Analyst owner
  assigned_to         UUID                       REFERENCES public.users(id)
                                                 ON DELETE SET NULL,

  -- Lifecycle timestamps
  first_seen_at       TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  contained_at        TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,

  -- Soft-delete
  deleted_at          TIMESTAMPTZ,

  -- Standard timestamps
  created_at          TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ                NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT incidents_title_length
    CHECK (char_length(title) BETWEEN 1 AND 500),
  CONSTRAINT incidents_confidence_range
    CHECK (confidence BETWEEN 0 AND 100),
  CONSTRAINT incidents_risk_score_range
    CHECK (risk_score BETWEEN 0 AND 100),
  CONSTRAINT incidents_threat_count_nonneg
    CHECK (threat_count >= 0),
  CONSTRAINT incidents_asset_count_nonneg
    CHECK (asset_count >= 0),
  CONSTRAINT incidents_last_after_first
    CHECK (last_seen_at >= first_seen_at),
  CONSTRAINT incidents_resolved_after_first
    CHECK (resolved_at IS NULL OR resolved_at >= first_seen_at),
  CONSTRAINT incidents_contained_after_first
    CHECK (contained_at IS NULL OR contained_at >= first_seen_at)
);

COMMENT ON TABLE  public.incidents                     IS 'Correlated threat groupings forming a single attack narrative.';
COMMENT ON COLUMN public.incidents.id                  IS 'UUID primary key.';
COMMENT ON COLUMN public.incidents.organization_id     IS 'Owning organization.';
COMMENT ON COLUMN public.incidents.short_id            IS 'Human-friendly short reference (e.g., INC-A3F2B9).';
COMMENT ON COLUMN public.incidents.title               IS 'AI-generated incident name.';
COMMENT ON COLUMN public.incidents.description         IS 'Full incident summary written by the Investigation Agent.';
COMMENT ON COLUMN public.incidents.severity            IS 'Highest severity among linked threats.';
COMMENT ON COLUMN public.incidents.status              IS 'Lifecycle status.';
COMMENT ON COLUMN public.incidents.priority            IS 'SOC priority: p1 (critical) through p4 (low).';
COMMENT ON COLUMN public.incidents.confidence          IS 'Aggregate AI confidence (0–100).';
COMMENT ON COLUMN public.incidents.risk_score          IS 'Aggregate risk score (0–100).';
COMMENT ON COLUMN public.incidents.threat_count        IS 'Cached count of linked threats.';
COMMENT ON COLUMN public.incidents.asset_count         IS 'Cached count of affected assets.';
COMMENT ON COLUMN public.incidents.kill_chain          IS 'Ordered MITRE tactic sequence reconstructed by the Investigation Agent.';
COMMENT ON COLUMN public.incidents.mitre_tactics       IS 'Deduplicated tactic IDs across all linked threats.';
COMMENT ON COLUMN public.incidents.mitre_techniques    IS 'Deduplicated technique IDs across all linked threats.';
COMMENT ON COLUMN public.incidents.affected_asset_ids  IS 'All assets involved in this incident.';
COMMENT ON COLUMN public.incidents.source_ips          IS 'All attacker IPs across linked threats.';
COMMENT ON COLUMN public.incidents.attribution         IS 'Suspected threat actor, campaign, malware family.';
COMMENT ON COLUMN public.incidents.timeline            IS 'Forensics Agent timeline reconstruction (ordered JSON events).';
COMMENT ON COLUMN public.incidents.playbook_runs       IS 'Response Agent action log (playbooks executed and outcomes).';
COMMENT ON COLUMN public.incidents.ai_summary          IS 'Investigation Agent reasoning trail and decisions.';
COMMENT ON COLUMN public.incidents.tags                IS 'Free-form labels.';
COMMENT ON COLUMN public.incidents.assigned_to         IS 'Analyst owning this incident.';
COMMENT ON COLUMN public.incidents.first_seen_at       IS 'Earliest detected_at among linked threats.';
COMMENT ON COLUMN public.incidents.last_seen_at        IS 'Most recent threat activity in this incident.';
COMMENT ON COLUMN public.incidents.contained_at        IS 'When the incident transitioned to contained status.';
COMMENT ON COLUMN public.incidents.resolved_at         IS 'When the incident was closed.';
COMMENT ON COLUMN public.incidents.deleted_at          IS 'Soft-delete timestamp.';


-- Main incident feed (most recent first, active only)
CREATE INDEX IF NOT EXISTS idx_incidents_org_last_seen_at
  ON public.incidents(organization_id, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Active incidents (open, investigating, contained)
CREATE INDEX IF NOT EXISTS idx_incidents_active
  ON public.incidents(organization_id, priority, last_seen_at DESC)
  WHERE deleted_at IS NULL
    AND status IN ('open', 'investigating', 'contained');

-- Priority queue (P1 first, then P2, etc.)
CREATE INDEX IF NOT EXISTS idx_incidents_priority
  ON public.incidents(organization_id, priority, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Severity filtering
CREATE INDEX IF NOT EXISTS idx_incidents_severity
  ON public.incidents(organization_id, severity, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Status filtering
CREATE INDEX IF NOT EXISTS idx_incidents_status
  ON public.incidents(organization_id, status, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Risk score ranking
CREATE INDEX IF NOT EXISTS idx_incidents_risk_score
  ON public.incidents(organization_id, risk_score DESC, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Assigned-to queue (analyst dashboard)
CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to
  ON public.incidents(assigned_to, status, last_seen_at DESC)
  WHERE assigned_to IS NOT NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_incidents_short_id
  ON public.incidents(short_id);

-- Affected asset lookups (find incidents touching this asset)
CREATE INDEX IF NOT EXISTS idx_incidents_affected_assets
  ON public.incidents USING GIN(affected_asset_ids);

-- MITRE-based search
CREATE INDEX IF NOT EXISTS idx_incidents_mitre_techniques
  ON public.incidents USING GIN(mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_incidents_mitre_tactics
  ON public.incidents USING GIN(mitre_tactics);

-- Attacker IP correlation
CREATE INDEX IF NOT EXISTS idx_incidents_source_ips
  ON public.incidents USING GIN(source_ips);

-- Tag search
CREATE INDEX IF NOT EXISTS idx_incidents_tags
  ON public.incidents USING GIN(tags);

-- Attribution search (find all APT29 incidents)
CREATE INDEX IF NOT EXISTS idx_incidents_attribution
  ON public.incidents USING GIN(attribution);


DROP TRIGGER IF EXISTS set_incidents_updated_at ON public.incidents;

CREATE TRIGGER set_incidents_updated_at
  BEFORE UPDATE ON public.incidents
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.set_incident_status_timestamps()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  -- contained_at stamps on first transition to 'contained'
  IF NEW.status = 'contained'
     AND (OLD.status IS NULL OR OLD.status <> 'contained')
     AND NEW.contained_at IS NULL THEN
    NEW.contained_at := NOW();
  END IF;

  -- resolved_at stamps on first transition to a terminal state
  IF NEW.status IN ('resolved', 'closed', 'false_positive')
     AND OLD.status NOT IN ('resolved', 'closed', 'false_positive')
     AND NEW.resolved_at IS NULL THEN
    NEW.resolved_at := NOW();
  END IF;

  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.set_incident_status_timestamps() IS
  'Auto-stamps contained_at and resolved_at when incident status transitions.';

DROP TRIGGER IF EXISTS set_incidents_status_timestamps ON public.incidents;

CREATE TRIGGER set_incidents_status_timestamps
  BEFORE UPDATE OF status ON public.incidents
  FOR EACH ROW
  EXECUTE FUNCTION public.set_incident_status_timestamps();


ALTER TABLE public.threats
  DROP CONSTRAINT IF EXISTS threats_incident_id_fkey;

ALTER TABLE public.threats
  ADD CONSTRAINT threats_incident_id_fkey
  FOREIGN KEY (incident_id)
  REFERENCES public.incidents(id)
  ON DELETE SET NULL;


ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
