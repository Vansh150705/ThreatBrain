DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'event_source') THEN
    CREATE TYPE public.event_source AS ENUM (
      'edr',           -- endpoint detection & response (CrowdStrike, SentinelOne)
      'firewall',      -- network firewall logs
      'cloud_audit',   -- AWS CloudTrail, GCP audit, Azure activity
      'siem',          -- forwarded from another SIEM
      'dns',           -- DNS query logs
      'application',   -- application-layer logs
      'authentication',-- auth/identity events
      'email',         -- email gateway alerts
      'manual',        -- analyst-created event
      'simulator',     -- ThreatBrain log simulator (for demo)
      'other'
    );
  END IF;
END$$;

COMMENT ON TYPE public.event_source IS
  'Origin of an event (which log source or sensor produced it).';


CREATE TABLE IF NOT EXISTS public.events (
  id                UUID                 PRIMARY KEY
                                         DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id   UUID                 NOT NULL
                                         REFERENCES public.organizations(id)
                                         ON DELETE CASCADE,

  -- Linked asset (nullable — some events may not map to a known asset yet)
  asset_id          UUID                 REFERENCES public.assets(id)
                                         ON DELETE SET NULL,

  -- Human-friendly short reference (e.g., "EVT-A3F2B9")
  short_id          TEXT                 NOT NULL
                                         DEFAULT public.generate_short_id('EVT'),

  -- Where this event came from
  source            public.event_source  NOT NULL,

  -- Category (free-form but conventionally dotted, e.g.
  -- "authentication.failed", "process.suspicious_powershell",
  -- "network.c2_beacon", "cloud.s3_bucket_public")
  event_type        TEXT                 NOT NULL,

  -- AI-scored severity (initial from source; Triage Agent may override)
  severity          public.severity_level NOT NULL DEFAULT 'info',

  -- Human-readable
  title             TEXT                 NOT NULL,
  description       TEXT,

  -- Network identifiers (nullable — not all events are network-related)
  source_ip         INET,
  destination_ip    INET,
  source_port       INTEGER,
  destination_port  INTEGER,

  -- Identity / process / file context
  username          TEXT,
  process_name      TEXT,
  command_line      TEXT,
  file_hash         TEXT,

  -- Full original payload — analysts can drill down to raw data
  raw_data          JSONB                NOT NULL DEFAULT '{}'::jsonb,

  -- Flexible labels (e.g., ['mitre:T1059', 'campaign:apt29'])
  tags              TEXT[]               NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Processing state — has the Triage Agent reviewed this event?
  processed         BOOLEAN              NOT NULL DEFAULT FALSE,
  processed_at      TIMESTAMPTZ,

  -- Promotion to a threat (FK constraint added in migration 006)
  threat_id         UUID,

  -- Timestamps
  observed_at       TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
  ingested_at       TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
  created_at        TIMESTAMPTZ          NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ          NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT events_title_length
    CHECK (char_length(title) BETWEEN 1 AND 500),
  CONSTRAINT events_event_type_length
    CHECK (char_length(event_type) BETWEEN 1 AND 100),
  CONSTRAINT events_source_port_range
    CHECK (source_port IS NULL OR (source_port BETWEEN 0 AND 65535)),
  CONSTRAINT events_destination_port_range
    CHECK (destination_port IS NULL OR (destination_port BETWEEN 0 AND 65535)),
  CONSTRAINT events_command_line_length
    CHECK (command_line IS NULL OR char_length(command_line) <= 8000)
);

COMMENT ON TABLE  public.events                  IS 'Raw security telemetry ingested from logs, EDR, cloud, etc.';
COMMENT ON COLUMN public.events.id               IS 'UUID primary key.';
COMMENT ON COLUMN public.events.organization_id  IS 'Owning organization.';
COMMENT ON COLUMN public.events.asset_id         IS 'Linked asset (nullable if asset unknown).';
COMMENT ON COLUMN public.events.short_id         IS 'Human-friendly short reference (e.g., EVT-A3F2B9).';
COMMENT ON COLUMN public.events.source           IS 'Sensor or log source that produced the event.';
COMMENT ON COLUMN public.events.event_type       IS 'Category (e.g., authentication.failed, network.c2_beacon).';
COMMENT ON COLUMN public.events.severity         IS 'Severity (initial from source; Triage Agent may revise).';
COMMENT ON COLUMN public.events.title            IS 'One-line summary shown in lists and feeds.';
COMMENT ON COLUMN public.events.description      IS 'Longer human-readable explanation.';
COMMENT ON COLUMN public.events.source_ip        IS 'IP that triggered the event (INET).';
COMMENT ON COLUMN public.events.destination_ip   IS 'Target IP (INET).';
COMMENT ON COLUMN public.events.username         IS 'Subject user (if applicable).';
COMMENT ON COLUMN public.events.process_name     IS 'Process name (if applicable).';
COMMENT ON COLUMN public.events.command_line     IS 'Command line invocation (truncated to 8000 chars).';
COMMENT ON COLUMN public.events.file_hash        IS 'File hash IOC (MD5/SHA1/SHA256).';
COMMENT ON COLUMN public.events.raw_data         IS 'Full original payload as JSONB.';
COMMENT ON COLUMN public.events.tags             IS 'Free-form labels for filtering and correlation.';
COMMENT ON COLUMN public.events.processed        IS 'TRUE once the Triage Agent has reviewed it.';
COMMENT ON COLUMN public.events.processed_at     IS 'Timestamp when Triage Agent processed the event.';
COMMENT ON COLUMN public.events.threat_id        IS 'Linked threat if this event was promoted (FK added in migration 006).';
COMMENT ON COLUMN public.events.observed_at      IS 'Timestamp from the source system (when the event actually happened).';
COMMENT ON COLUMN public.events.ingested_at      IS 'Timestamp when ThreatBrain received the event.';


-- Time-range queries scoped to an organization (most common access pattern)
CREATE INDEX IF NOT EXISTS idx_events_org_observed_at
  ON public.events(organization_id, observed_at DESC);

-- Unprocessed events queue (Triage Agent polling)
CREATE INDEX IF NOT EXISTS idx_events_unprocessed
  ON public.events(organization_id, ingested_at ASC)
  WHERE processed = FALSE;

-- Events for a specific asset
CREATE INDEX IF NOT EXISTS idx_events_asset
  ON public.events(asset_id, observed_at DESC)
  WHERE asset_id IS NOT NULL;

-- Events promoted to threats
CREATE INDEX IF NOT EXISTS idx_events_threat_id
  ON public.events(threat_id)
  WHERE threat_id IS NOT NULL;

-- Severity-filtered feeds
CREATE INDEX IF NOT EXISTS idx_events_severity
  ON public.events(organization_id, severity, observed_at DESC);

-- Event type filtering and counting
CREATE INDEX IF NOT EXISTS idx_events_event_type
  ON public.events(organization_id, event_type);

-- Source-based filtering
CREATE INDEX IF NOT EXISTS idx_events_source
  ON public.events(organization_id, source);

-- IP-based correlation (find all events from this attacker IP)
CREATE INDEX IF NOT EXISTS idx_events_source_ip
  ON public.events(source_ip)
  WHERE source_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_events_destination_ip
  ON public.events(destination_ip)
  WHERE destination_ip IS NOT NULL;

-- User-based correlation
CREATE INDEX IF NOT EXISTS idx_events_username
  ON public.events(organization_id, username)
  WHERE username IS NOT NULL;

-- File hash IOC search
CREATE INDEX IF NOT EXISTS idx_events_file_hash
  ON public.events(file_hash)
  WHERE file_hash IS NOT NULL;

-- Tag search (GIN — fast array contains queries)
CREATE INDEX IF NOT EXISTS idx_events_tags
  ON public.events USING GIN(tags);

-- Raw JSON drill-down search
CREATE INDEX IF NOT EXISTS idx_events_raw_data
  ON public.events USING GIN(raw_data);

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_events_short_id
  ON public.events(short_id);


DROP TRIGGER IF EXISTS set_events_updated_at ON public.events;

CREATE TRIGGER set_events_updated_at
  BEFORE UPDATE ON public.events
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;
