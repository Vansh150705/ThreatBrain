DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'plan_tier') THEN
    CREATE TYPE public.plan_tier AS ENUM (
      'free',
      'pro',
      'enterprise'
    );
  END IF;
END$$;

COMMENT ON TYPE public.plan_tier IS
  'Subscription plan tiers for organizations.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'org_status') THEN
    CREATE TYPE public.org_status AS ENUM (
      'trial',
      'active',
      'suspended',
      'cancelled'
    );
  END IF;
END$$;

COMMENT ON TYPE public.org_status IS
  'Lifecycle state of an organization account.';


CREATE TABLE IF NOT EXISTS public.organizations (
  id            UUID            PRIMARY KEY  DEFAULT extensions.uuid_generate_v4(),

  -- Display name shown in UI (e.g., "Acme Corporation")
  name          TEXT            NOT NULL,

  -- URL-safe unique identifier (e.g., "acme-corp")
  -- Used in URLs, API paths, and as a stable external reference.
  slug          TEXT            NOT NULL  UNIQUE,

  -- Subscription tier (free / pro / enterprise)
  plan          public.plan_tier NOT NULL  DEFAULT 'free',

  -- Account lifecycle status
  status        public.org_status NOT NULL DEFAULT 'trial',

  -- Free-form configuration (notification prefs, integrations, etc.)
  -- Defaulted to an empty JSON object so downstream code never deals with NULL.
  settings      JSONB           NOT NULL  DEFAULT '{}'::jsonb,

  -- Optional billing/contact email at the org level
  billing_email TEXT,

  -- Soft-delete support (NULL = active record)
  deleted_at    TIMESTAMPTZ,

  -- Standard timestamps
  created_at    TIMESTAMPTZ     NOT NULL  DEFAULT NOW(),
  updated_at    TIMESTAMPTZ     NOT NULL  DEFAULT NOW(),

  -- Constraints
  CONSTRAINT organizations_slug_format
    CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
  CONSTRAINT organizations_name_length
    CHECK (char_length(name) BETWEEN 2 AND 120),
  CONSTRAINT organizations_slug_length
    CHECK (char_length(slug) BETWEEN 2 AND 60)
);

COMMENT ON TABLE  public.organizations              IS 'Multi-tenant organizations using ThreatBrain.';
COMMENT ON COLUMN public.organizations.id           IS 'UUID primary key.';
COMMENT ON COLUMN public.organizations.name         IS 'Human-readable organization name.';
COMMENT ON COLUMN public.organizations.slug         IS 'URL-safe unique identifier (e.g., "acme-corp").';
COMMENT ON COLUMN public.organizations.plan         IS 'Subscription tier: free, pro, or enterprise.';
COMMENT ON COLUMN public.organizations.status       IS 'Lifecycle status: trial, active, suspended, cancelled.';
COMMENT ON COLUMN public.organizations.settings     IS 'Free-form JSONB for organization-level configuration.';
COMMENT ON COLUMN public.organizations.billing_email IS 'Optional billing/contact email.';
COMMENT ON COLUMN public.organizations.deleted_at   IS 'Soft-delete timestamp (NULL = active).';


-- Look up active orgs by status (e.g., billing jobs, dashboards)
CREATE INDEX IF NOT EXISTS idx_organizations_status
  ON public.organizations(status)
  WHERE deleted_at IS NULL;

-- Look up orgs by plan tier (e.g., feature gating queries)
CREATE INDEX IF NOT EXISTS idx_organizations_plan
  ON public.organizations(plan)
  WHERE deleted_at IS NULL;

-- Created-at index for time-series dashboards
CREATE INDEX IF NOT EXISTS idx_organizations_created_at
  ON public.organizations(created_at DESC);


DROP TRIGGER IF EXISTS set_organizations_updated_at ON public.organizations;

CREATE TRIGGER set_organizations_updated_at
  BEFORE UPDATE ON public.organizations
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
