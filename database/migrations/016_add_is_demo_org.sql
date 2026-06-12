-- ============================================================================
-- 016_add_is_demo_org.sql
-- Adds a flag distinguishing demo/self-signup workspaces from real tenants,
-- so future cleanup jobs can target them without touching paying orgs.
-- ============================================================================

ALTER TABLE public.organizations
ADD COLUMN IF NOT EXISTS is_demo_org BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN public.organizations.is_demo_org IS
  'TRUE for demo/self-signup workspaces (including the seeded Acme org). Used by cleanup jobs.';

-- Mark the existing Acme Corporation as a demo org so it's distinguishable
UPDATE public.organizations
SET is_demo_org = TRUE
WHERE id = '00000000-0000-0000-0000-00000000ac01';

-- Index for future cleanup queries
CREATE INDEX IF NOT EXISTS idx_organizations_demo
ON public.organizations(is_demo_org, created_at)
WHERE is_demo_org = TRUE;
