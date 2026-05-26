DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ioc_type') THEN
    CREATE TYPE public.ioc_type AS ENUM (
      'ipv4',
      'ipv6',
      'domain',
      'url',
      'md5',
      'sha1',
      'sha256',
      'email',
      'cve',          -- vulnerability identifier
      'mutex',        -- malware mutex
      'registry',     -- Windows registry key
      'filename',
      'user_agent',
      'asn',
      'other'
    );
  END IF;
END$$;

COMMENT ON TYPE public.ioc_type IS
  'Category of indicator of compromise.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'reputation_level') THEN
    CREATE TYPE public.reputation_level AS ENUM (
      'unknown',
      'benign',
      'suspicious',
      'malicious'
    );
  END IF;
END$$;

COMMENT ON TYPE public.reputation_level IS
  'Reputation verdict for an IOC.';


CREATE TABLE IF NOT EXISTS public.iocs (
  id                  UUID                       PRIMARY KEY
                                                 DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope
  organization_id     UUID                       NOT NULL
                                                 REFERENCES public.organizations(id)
                                                 ON DELETE CASCADE,

  -- Human-friendly short reference (e.g., "IOC-A3F2B9")
  short_id            TEXT                       NOT NULL
                                                 DEFAULT public.generate_short_id('IOC'),

  -- Indicator classification
  ioc_type            public.ioc_type            NOT NULL,

  -- Raw value as observed (preserves original casing, e.g., URLs)
  value               TEXT                       NOT NULL,

  -- Canonical / normalized form for deduplication and lookups
  -- (lowercased for domains/emails/hashes, IP parsed, URL canonicalized)
  -- Auto-populated by a trigger below.
  normalized_value    TEXT                       NOT NULL,

  -- Verdict
  reputation          public.reputation_level    NOT NULL DEFAULT 'unknown',

  -- Confidence in the reputation verdict (0–100)
  confidence          SMALLINT                   NOT NULL DEFAULT 0,

  -- Aggregated threat score from external feeds (0–100)
  -- (e.g., AbuseIPDB confidence_score, VT detection ratio, etc.)
  threat_score        SMALLINT                   NOT NULL DEFAULT 0,

  -- Free-form labels (e.g., ['c2', 'apt29', 'phishing', 'ransomware'])
  tags                TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Which external feeds reported this IOC
  source_feeds        TEXT[]                     NOT NULL DEFAULT ARRAY[]::TEXT[],

  -- Raw per-feed responses (keyed by feed name)
  -- e.g., {"abuseipdb": {...}, "virustotal": {...}, "shodan": {...}}
  enrichment          JSONB                      NOT NULL DEFAULT '{}'::jsonb,

  -- Cross-references (threats/incidents that mentioned this IOC)
  related_threats     UUID[]                     NOT NULL DEFAULT ARRAY[]::UUID[],
  related_incidents   UUID[]                     NOT NULL DEFAULT ARRAY[]::UUID[],

  -- Sighting tracking
  times_seen          INTEGER                    NOT NULL DEFAULT 1,

  -- Geo-IP context (for IP-type IOCs)
  geo_country         TEXT,                                  -- ISO 3166-1 alpha-2 (e.g., "RU", "CN")
  geo_city            TEXT,
  asn                 INTEGER,                               -- Autonomous System Number

  -- Lifecycle timestamps
  first_seen_at       TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ                NOT NULL DEFAULT NOW(),

  -- When the cached reputation should be re-verified
  -- (e.g., re-check malicious IPs every 24h, benign domains every 7 days)
  expires_at          TIMESTAMPTZ,

  -- Soft-delete
  deleted_at          TIMESTAMPTZ,

  -- Standard timestamps
  created_at          TIMESTAMPTZ                NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ                NOT NULL DEFAULT NOW(),

  -- Constraints
  CONSTRAINT iocs_value_length
    CHECK (char_length(value) BETWEEN 1 AND 2048),
  CONSTRAINT iocs_normalized_value_length
    CHECK (char_length(normalized_value) BETWEEN 1 AND 2048),
  CONSTRAINT iocs_confidence_range
    CHECK (confidence BETWEEN 0 AND 100),
  CONSTRAINT iocs_threat_score_range
    CHECK (threat_score BETWEEN 0 AND 100),
  CONSTRAINT iocs_times_seen_nonneg
    CHECK (times_seen >= 0),
  CONSTRAINT iocs_geo_country_format
    CHECK (geo_country IS NULL OR char_length(geo_country) = 2),
  CONSTRAINT iocs_last_after_first
    CHECK (last_seen_at >= first_seen_at)
);

COMMENT ON TABLE  public.iocs                     IS 'Indicators of Compromise — cached threat intel for IPs, hashes, domains, etc.';
COMMENT ON COLUMN public.iocs.id                  IS 'UUID primary key.';
COMMENT ON COLUMN public.iocs.organization_id     IS 'Owning organization.';
COMMENT ON COLUMN public.iocs.short_id            IS 'Human-friendly short reference.';
COMMENT ON COLUMN public.iocs.ioc_type            IS 'Indicator category (ipv4, domain, sha256, etc.).';
COMMENT ON COLUMN public.iocs.value               IS 'Raw indicator value as observed.';
COMMENT ON COLUMN public.iocs.normalized_value    IS 'Canonical form for deduplication (auto-populated).';
COMMENT ON COLUMN public.iocs.reputation          IS 'Reputation verdict (unknown, benign, suspicious, malicious).';
COMMENT ON COLUMN public.iocs.confidence          IS 'Confidence in the verdict (0–100).';
COMMENT ON COLUMN public.iocs.threat_score        IS 'Aggregated threat score from external feeds (0–100).';
COMMENT ON COLUMN public.iocs.tags                IS 'Free-form labels (c2, apt29, phishing, etc.).';
COMMENT ON COLUMN public.iocs.source_feeds        IS 'External feeds that reported this IOC.';
COMMENT ON COLUMN public.iocs.enrichment          IS 'Raw per-feed enrichment responses.';
COMMENT ON COLUMN public.iocs.related_threats     IS 'Threats that referenced this IOC.';
COMMENT ON COLUMN public.iocs.related_incidents   IS 'Incidents that referenced this IOC.';
COMMENT ON COLUMN public.iocs.times_seen          IS 'Sighting counter.';
COMMENT ON COLUMN public.iocs.geo_country         IS 'ISO 3166-1 alpha-2 country code (for IP IOCs).';
COMMENT ON COLUMN public.iocs.geo_city            IS 'City (for IP IOCs).';
COMMENT ON COLUMN public.iocs.asn                 IS 'Autonomous System Number (for IP IOCs).';
COMMENT ON COLUMN public.iocs.first_seen_at       IS 'When this IOC was first observed.';
COMMENT ON COLUMN public.iocs.last_seen_at        IS 'Most recent sighting.';
COMMENT ON COLUMN public.iocs.expires_at          IS 'When the cached reputation should be re-verified.';
COMMENT ON COLUMN public.iocs.deleted_at          IS 'Soft-delete timestamp.';


CREATE OR REPLACE FUNCTION public.normalize_ioc_value()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.normalized_value := CASE NEW.ioc_type
    WHEN 'ipv4'     THEN trim(NEW.value)
    WHEN 'ipv6'     THEN lower(trim(NEW.value))
    WHEN 'domain'   THEN lower(trim(NEW.value))
    WHEN 'url'      THEN lower(trim(NEW.value))
    WHEN 'md5'      THEN lower(trim(NEW.value))
    WHEN 'sha1'     THEN lower(trim(NEW.value))
    WHEN 'sha256'   THEN lower(trim(NEW.value))
    WHEN 'email'    THEN lower(trim(NEW.value))
    WHEN 'cve'      THEN upper(trim(NEW.value))   -- "CVE-2023-1234"
    ELSE trim(NEW.value)
  END;
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.normalize_ioc_value() IS
  'Auto-populates normalized_value with a canonicalized form of value for deduplication.';

DROP TRIGGER IF EXISTS normalize_iocs_value ON public.iocs;

CREATE TRIGGER normalize_iocs_value
  BEFORE INSERT OR UPDATE OF value, ioc_type ON public.iocs
  FOR EACH ROW
  EXECUTE FUNCTION public.normalize_ioc_value();


-- One row per (org, type, normalized value) — prevents duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_org_type_value_unique
  ON public.iocs(organization_id, ioc_type, normalized_value)
  WHERE deleted_at IS NULL;

-- Main IOC feed (most recent first)
CREATE INDEX IF NOT EXISTS idx_iocs_org_last_seen_at
  ON public.iocs(organization_id, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Reputation-filtered feeds ("show me all malicious IOCs")
CREATE INDEX IF NOT EXISTS idx_iocs_reputation
  ON public.iocs(organization_id, reputation, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Type-filtered queries
CREATE INDEX IF NOT EXISTS idx_iocs_ioc_type
  ON public.iocs(organization_id, ioc_type, last_seen_at DESC)
  WHERE deleted_at IS NULL;

-- Threat-score ranking ("top malicious IOCs")
CREATE INDEX IF NOT EXISTS idx_iocs_threat_score
  ON public.iocs(organization_id, threat_score DESC, last_seen_at DESC)
  WHERE deleted_at IS NULL
    AND reputation IN ('suspicious', 'malicious');

-- Expiration scan ("which IOCs need re-verification?")
CREATE INDEX IF NOT EXISTS idx_iocs_expires_at
  ON public.iocs(expires_at)
  WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

-- Short-ID lookup
CREATE INDEX IF NOT EXISTS idx_iocs_short_id
  ON public.iocs(short_id);

-- Geo-based queries (attack map: "show me all malicious IPs from Russia")
CREATE INDEX IF NOT EXISTS idx_iocs_geo_country
  ON public.iocs(organization_id, geo_country)
  WHERE geo_country IS NOT NULL AND deleted_at IS NULL;

-- Tag search
CREATE INDEX IF NOT EXISTS idx_iocs_tags
  ON public.iocs USING GIN(tags);

-- Cross-reference search
CREATE INDEX IF NOT EXISTS idx_iocs_related_threats
  ON public.iocs USING GIN(related_threats);

CREATE INDEX IF NOT EXISTS idx_iocs_related_incidents
  ON public.iocs USING GIN(related_incidents);

-- Raw enrichment drill-down
CREATE INDEX IF NOT EXISTS idx_iocs_enrichment
  ON public.iocs USING GIN(enrichment);

-- Source feed filtering
CREATE INDEX IF NOT EXISTS idx_iocs_source_feeds
  ON public.iocs USING GIN(source_feeds);


DROP TRIGGER IF EXISTS set_iocs_updated_at ON public.iocs;

CREATE TRIGGER set_iocs_updated_at
  BEFORE UPDATE ON public.iocs
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


ALTER TABLE public.iocs ENABLE ROW LEVEL SECURITY;
