CREATE TABLE IF NOT EXISTS public.threats (
  id                  UUID                  PRIMARY KEY
                                            DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id     UUID                  NOT NULL
                                            REFERENCES public.organizations(id)
                                            ON DELETE CASCADE,

  -- Human-friendly short reference (e.g., "THR-7C4E11")
  short_id            TEXT                  NOT NULL
                                            DEFAULT public.generate_short_id('THR'),

  -- Primary affected asset (a threat may touch others, but one is the focus)
  primary_asset_id    UUID                  REFERENCES public.assets(id)
                                            ON DELETE SET NULL,

  -- Grouped into a larger incident? (FK added in migration 007)
  incident_id         UUID,

  -- Human-readable
  title               TEXT                  NOT NULL,
  description         TEXT,

  -- AI verdict
  severity            public.severity_level NOT NULL DEFAULT 'medium',
  status              public.status_level   NOT NULL DEFAULT 'open',

  -- Confidence: 0–100, how sure the AI is this is a real threat
  confidence          SMALLINT              NOT NULL DEFAULT 50,

  -- Risk score: 0–100, combines severity + asset criticality + confidence
  risk_score          SMALLINT              NOT NULL DEFAULT 0,

  -- MITRE ATT&CK mapping
  -- Tactics: high-level adversary goals (e.g., 'TA0001' Initial Access)
  -- Techniques: how they achieve them (e.g., 'T1110' Brute Force)
  mitre_tactics       TEXT[]                NOT NULL DEFAULT ARRAY[]::TEXT[],
  mitre_techniques    TEXT[]                NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Ordered attack-chain sequence reconstructed by Investigation Agent
  attack_chain        TEXT[]                NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Network indicators involved
  source_ips          INET[]                NOT NULL DEFAULT ARRAY[]::INET[],
  target_ips          INET[]                NOT NULL DEFAULT ARRAY[]::INET[],

  -- Affected users (subjects of the threat)
  affected_users      TEXT[]                NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Indicators of compromise (IPs, hashes, domains, etc.) as structured JSON
  iocs                JSONB                 NOT NULL DEFAULT '{}'::jsonb,

  -- Threat-intel enrichment from external feeds (AbuseIPDB, VirusTotal, etc.)
  enrichment          JSONB                 NOT NULL DEFAULT '{}'::jsonb,

  -- Raw AI reasoning + tool calls + intermediate steps (audit trail)
  ai_analysis         JSONB                 NOT NULL DEFAULT '{}'::jsonb,

  -- Free-form labels
  tags                TEXT[]                NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Analyst assigned to this threat (nullable — unassigned is valid)
  assigned_to         UUID                  REFERENCES public.users(id)
                                            ON DELETE SET NULL,

  -- Lifecycle timestamps
  detected_at         TIMESTAMPTZ           NOT NULL DEFAULT NOW(),
  resolved_at         TIMESTAMPTZ,

  -- Soft-delete
  deleted_at          TIMESTAMPTZ,

  -- Standard timestamps
  created_at          TIMESTAMPTZ           NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ           NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT threats_title_length
    CHECK (char_length(title) BETWEEN 1 AND 500),
  CONSTRAINT threats_confidence_range
    CHECK (confidence BETWEEN 0 AND 100),
  CONSTRAINT threats_risk_score_range
    CHECK (risk_score BETWEEN 0 AND 100),
  CONSTRAINT threats_resolved_after_detected
    CHECK (resolved_at IS NULL OR resolved_at >= detected_at)
);

COMMENT ON TABLE  public.threats                  IS 'AI-classified threats derived from events.';
COMMENT ON COLUMN public.threats.id               IS 'UUID primary key.';
COMMENT ON COLUMN public.threats.organization_id  IS 'Owning organization.';
COMMENT ON COLUMN public.threats.short_id         IS 'Human-friendly short reference (e.g., THR-7C4E11).';
COMMENT ON COLUMN public.threats.primary_asset_id IS 'Main affected asset.';
COMMENT ON COLUMN public.threats.incident_id      IS 'Linked incident if grouped into an attack chain (FK added in migration 007).';
COMMENT ON COLUMN public.threats.title            IS 'One-line summary shown in lists.';
COMMENT ON COLUMN public.threats.description      IS 'AI-generated longer explanation.';
COMMENT ON COLUMN public.threats.severity         IS 'Severity verdict (info, low, medium, high, critical).';
COMMENT ON COLUMN public.threats.status           IS 'Lifecycle status (open, investigating, resolved, etc.).';
COMMENT ON COLUMN public.threats.confidence       IS 'AI confidence that this is a real threat (0–100).';
COMMENT ON COLUMN public.threats.risk_score       IS 'Composite risk score (0–100): severity × criticality × confidence.';
COMMENT ON COLUMN public.threats.mitre_tactics    IS 'MITRE ATT&CK tactic IDs (e.g., TA0001, TA0006).';
COMMENT ON COLUMN public.threats.mitre_techniques IS 'MITRE ATT&CK technique IDs (e.g., T1110, T1078).';
COMMENT ON COLUMN public.threats.attack_chain     IS 'Ordered tactic sequence reconstructed by Investigation Agent.';
COMMENT ON COLUMN public.threats.source_ips       IS 'Attacker IPs involved (INET array).';
COMMENT ON COLUMN public.threats.target_ips       IS 'Victim IPs involved (INET array).';
COMMENT ON COLUMN public.threats.affected_users   IS 'Usernames affected by this threat.';
COMMENT ON COLUMN public.threats.iocs             IS 'Indicators of compromise (structured JSONB).';
COMMENT ON COLUMN public.threats.enrichment       IS 'Threat-intel enrichment from external feeds.';
COMMENT ON COLUMN public.threats.ai_analysis      IS 'Raw AI reasoning, tool calls, and intermediate steps.';
COMMENT ON COLUMN public.threats.tags             IS 'Free-form labels.';
COMMENT ON COLUMN public.threats.assigned_to      IS 'Analyst assigned to this threat (nullable).';
COMMENT ON COLUMN public.threats.detected_at      IS 'When the threat was first detected.';
COMMENT ON COLUMN public.threats.resolved_at      IS 'When the threat was closed (nullable while open).';
COMMENT ON COLUMN public.threats.deleted_at       IS 'Soft-delete timestamp.';


-- Time-range queries scoped to an organization (main feed)
CREATE INDEX IF NOT EXISTS idx_threats_org_detected_at
  ON public.threats(organization_id, detected_at DESC)
  WHERE deleted_at IS NULL;

-- Severity-filtered feeds (e.g., "show me criticals from last 24h")
CREATE INDEX IF NOT EXISTS idx_threats_severity
  ON public.threats(organization_id, severity, detected_at DESC)
  WHERE deleted_at IS NULL;

-- Status-filtered dashboards (open vs resolved)
CREATE INDEX IF NOT EXISTS idx_threats_status
  ON public.threats(organization_id, status, detected_at DESC)
  WHERE deleted_at IS NULL;

-- Active threats only (status != closed/resolved/false_positive)
CREATE INDEX IF NOT EXISTS idx_threats_active
  ON public.threats(organization_id, detected_at DESC)
  WHERE deleted_at IS NULL
    AND status IN ('open', 'investigating', 'contained');

-- Risk score ranking ("top risks right now")
CREATE INDEX IF NOT EXISTS idx_threats_risk_score
  ON public.threats(organization_id, risk_score DESC, detected_at DESC)
  WHERE deleted_at IS NULL;

-- Threats per asset
CREATE INDEX IF NOT EXISTS idx_threats_primary_asset
  ON public.threats(primary_asset_id, detected_at DESC)
  WHERE primary_asset_id IS NOT NULL;

-- Threats grouped into an incident
CREATE INDEX IF NOT EXISTS idx_threats_incident
  ON public.threats(incident_id)
  WHERE incident_id IS NOT NULL;

-- Threats assigned to a specific analyst
CREATE INDEX IF NOT EXISTS idx_threats_assigned_to
  ON public.threats(assigned_to, status, detected_at DESC)
  WHERE assigned_to IS NOT NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_threats_short_id
  ON public.threats(short_id);

-- MITRE technique search (GIN — find all threats using T1110)
CREATE INDEX IF NOT EXISTS idx_threats_mitre_techniques
  ON public.threats USING GIN(mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_threats_mitre_tactics
  ON public.threats USING GIN(mitre_tactics);

-- Source IP correlation (find all threats from this attacker IP)
CREATE INDEX IF NOT EXISTS idx_threats_source_ips
  ON public.threats USING GIN(source_ips);

-- Tag search
CREATE INDEX IF NOT EXISTS idx_threats_tags
  ON public.threats USING GIN(tags);

-- IOC drill-down
CREATE INDEX IF NOT EXISTS idx_threats_iocs
  ON public.threats USING GIN(iocs);


DROP TRIGGER IF EXISTS set_threats_updated_at ON public.threats;

CREATE TRIGGER set_threats_updated_at
  BEFORE UPDATE ON public.threats
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.set_threat_resolved_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status IN ('resolved', 'closed', 'false_positive')
     AND OLD.status NOT IN ('resolved', 'closed', 'false_positive')
     AND NEW.resolved_at IS NULL THEN
    NEW.resolved_at := NOW();
  END IF;
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.set_threat_resolved_at() IS
  'Auto-stamps resolved_at when threat status transitions to a terminal state.';

DROP TRIGGER IF EXISTS set_threats_resolved_at ON public.threats;

CREATE TRIGGER set_threats_resolved_at
  BEFORE UPDATE OF status ON public.threats
  FOR EACH ROW
  EXECUTE FUNCTION public.set_threat_resolved_at();


ALTER TABLE public.events
  DROP CONSTRAINT IF EXISTS events_threat_id_fkey;

ALTER TABLE public.events
  ADD CONSTRAINT events_threat_id_fkey
  FOREIGN KEY (threat_id)
  REFERENCES public.threats(id)
  ON DELETE SET NULL;


ALTER TABLE public.threats ENABLE ROW LEVEL SECURITY;
