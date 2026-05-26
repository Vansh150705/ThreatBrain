DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_type') THEN
    CREATE TYPE public.asset_type AS ENUM (
      'server',       -- physical or virtual server
      'endpoint',     -- laptop, desktop, workstation
      'cloud',        -- AWS account, GCP project, Azure subscription
      'network',      -- firewall, router, switch, load balancer
      'saas',         -- third-party SaaS app (GitHub, Slack, Okta, Salesforce)
      'database',     -- standalone DB instance
      'container',    -- Docker container, k8s pod
      'iot',          -- IoT device, sensor, embedded system
      'mobile',       -- mobile phone, tablet
      'other'         -- catch-all
    );
  END IF;
END$$;

COMMENT ON TYPE public.asset_type IS
  'Category of asset being monitored.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_environment') THEN
    CREATE TYPE public.asset_environment AS ENUM (
      'production',
      'staging',
      'development',
      'test',
      'unknown'
    );
  END IF;
END$$;

COMMENT ON TYPE public.asset_environment IS
  'Deployment environment of an asset.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_criticality') THEN
    CREATE TYPE public.asset_criticality AS ENUM (
      'low',
      'medium',
      'high',
      'crown_jewel'
    );
  END IF;
END$$;

COMMENT ON TYPE public.asset_criticality IS
  'Business-impact tier used by the Triage Agent for severity weighting.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'asset_status') THEN
    CREATE TYPE public.asset_status AS ENUM (
      'active',
      'inactive',
      'decommissioned'
    );
  END IF;
END$$;

COMMENT ON TYPE public.asset_status IS
  'Lifecycle status of an asset.';

CREATE TABLE IF NOT EXISTS public.assets (
  id                UUID                       PRIMARY KEY
                                               DEFAULT extensions.uuid_generate_v4(),

  -- Multi-tenant scope (every asset belongs to one org)
  organization_id   UUID                       NOT NULL
                                               REFERENCES public.organizations(id)
                                               ON DELETE CASCADE,

  -- Friendly display name (e.g., "prod-web-01")
  name              TEXT                       NOT NULL,

  -- Asset category
  asset_type        public.asset_type          NOT NULL,

  -- Where it lives
  environment       public.asset_environment   NOT NULL  DEFAULT 'unknown',

  -- Business-impact tier (drives Triage Agent severity weighting)
  criticality       public.asset_criticality   NOT NULL  DEFAULT 'medium',

  -- Network identity
  ip_address        INET,
  hostname          TEXT,

  -- System details
  operating_system  TEXT,
  os_version        TEXT,

  -- Who owns / is responsible for this asset
  owner_user_id     UUID                       REFERENCES public.users(id)
                                               ON DELETE SET NULL,

  -- Flexible labeling (e.g., ['pci-dss', 'payments', 'east-region'])
  tags              TEXT[]                     NOT NULL  DEFAULT ARRAY[]::TEXT[],

  -- Arbitrary integration data (AWS resource ARN, k8s labels, etc.)
  metadata          JSONB                      NOT NULL  DEFAULT '{}'::jsonb,

  -- Lifecycle
  status            public.asset_status        NOT NULL  DEFAULT 'active',

  -- Activity tracking — used to flag stale/orphaned assets
  last_seen_at      TIMESTAMPTZ,

  -- Soft-delete
  deleted_at        TIMESTAMPTZ,

  -- Standard timestamps
  created_at        TIMESTAMPTZ                NOT NULL  DEFAULT NOW(),
  updated_at        TIMESTAMPTZ                NOT NULL  DEFAULT NOW(),

  -- Constraints
  CONSTRAINT assets_name_length
    CHECK (char_length(name) BETWEEN 1 AND 200),
  CONSTRAINT assets_hostname_length
    CHECK (hostname IS NULL OR char_length(hostname) <= 253)
);

COMMENT ON TABLE  public.assets                  IS 'Resources protected by ThreatBrain (servers, endpoints, cloud accounts, etc.).';
COMMENT ON COLUMN public.assets.id               IS 'UUID primary key.';
COMMENT ON COLUMN public.assets.organization_id  IS 'Organization that owns this asset.';
COMMENT ON COLUMN public.assets.name             IS 'Human-readable asset name (e.g., "prod-web-01").';
COMMENT ON COLUMN public.assets.asset_type       IS 'Category: server, endpoint, cloud, network, saas, etc.';
COMMENT ON COLUMN public.assets.environment      IS 'Deployment environment.';
COMMENT ON COLUMN public.assets.criticality      IS 'Business-impact tier; read by the Triage Agent.';
COMMENT ON COLUMN public.assets.ip_address       IS 'Primary IP address (INET — supports IPv4 and IPv6).';
COMMENT ON COLUMN public.assets.hostname         IS 'DNS hostname (FQDN).';
COMMENT ON COLUMN public.assets.operating_system IS 'Operating system name (e.g., "Ubuntu", "Windows Server").';
COMMENT ON COLUMN public.assets.os_version       IS 'OS version (e.g., "22.04", "2022").';
COMMENT ON COLUMN public.assets.owner_user_id    IS 'User responsible for this asset.';
COMMENT ON COLUMN public.assets.tags             IS 'Free-form label array for compliance scopes, regions, etc.';
COMMENT ON COLUMN public.assets.metadata         IS 'Integration-specific data (AWS ARN, k8s labels, etc.).';
COMMENT ON COLUMN public.assets.status           IS 'Lifecycle status: active, inactive, decommissioned.';
COMMENT ON COLUMN public.assets.last_seen_at     IS 'Timestamp of last activity observed from this asset.';
COMMENT ON COLUMN public.assets.deleted_at       IS 'Soft-delete timestamp (NULL = active).';


-- Most queries scope to a specific organization
CREATE INDEX IF NOT EXISTS idx_assets_organization_id
  ON public.assets(organization_id)
  WHERE deleted_at IS NULL;

-- Unique asset name per organization (prevents duplicate entries)
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_org_name_unique
  ON public.assets(organization_id, lower(name))
  WHERE deleted_at IS NULL;

-- Type-based filtering (e.g., "show me all cloud assets")
CREATE INDEX IF NOT EXISTS idx_assets_type
  ON public.assets(organization_id, asset_type)
  WHERE deleted_at IS NULL;

-- Criticality filtering (Triage Agent queries)
CREATE INDEX IF NOT EXISTS idx_assets_criticality
  ON public.assets(organization_id, criticality)
  WHERE deleted_at IS NULL;

-- Environment filtering (separate prod from dev dashboards)
CREATE INDEX IF NOT EXISTS idx_assets_environment
  ON public.assets(organization_id, environment)
  WHERE deleted_at IS NULL;

-- IP-based lookups (when correlating events to assets)
CREATE INDEX IF NOT EXISTS idx_assets_ip_address
  ON public.assets(ip_address)
  WHERE ip_address IS NOT NULL AND deleted_at IS NULL;

-- Hostname lookups (case-insensitive)
CREATE INDEX IF NOT EXISTS idx_assets_hostname
  ON public.assets(lower(hostname))
  WHERE hostname IS NOT NULL AND deleted_at IS NULL;

-- Tag search (GIN index for fast array contains queries)
CREATE INDEX IF NOT EXISTS idx_assets_tags
  ON public.assets USING GIN(tags);

-- JSONB metadata search
CREATE INDEX IF NOT EXISTS idx_assets_metadata
  ON public.assets USING GIN(metadata);


DROP TRIGGER IF EXISTS set_assets_updated_at ON public.assets;

CREATE TRIGGER set_assets_updated_at
  BEFORE UPDATE ON public.assets
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;
