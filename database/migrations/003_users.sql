DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
    CREATE TYPE public.user_role AS ENUM (
      'owner',
      'admin',
      'analyst',
      'viewer'
    );
  END IF;
END$$;

COMMENT ON TYPE public.user_role IS
  'Permission tier for a user within their organization.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
    CREATE TYPE public.user_status AS ENUM (
      'invited',
      'active',
      'disabled'
    );
  END IF;
END$$;

COMMENT ON TYPE public.user_status IS
  'Lifecycle status of a user account.';

CREATE TABLE IF NOT EXISTS public.users (
  -- Mirrors auth.users.id (1:1 relationship enforced by FK).
  -- ON DELETE CASCADE means deleting an auth user wipes their profile.
  id              UUID            PRIMARY KEY
                                  REFERENCES auth.users(id) ON DELETE CASCADE,

  -- Each user belongs to exactly one organization.
  -- SET NULL on org delete so we can audit orphaned accounts before cleanup.
  organization_id UUID            REFERENCES public.organizations(id) ON DELETE SET NULL,

  -- Cached from auth.users for query performance (kept in sync via trigger).
  email           TEXT            NOT NULL,

  -- Display name shown in the UI
  full_name       TEXT,

  -- Permission tier within the organization
  role            public.user_role NOT NULL  DEFAULT 'viewer',

  -- Account lifecycle status
  status          public.user_status NOT NULL DEFAULT 'invited',

  -- Profile picture URL (e.g., from auth provider or uploaded)
  avatar_url      TEXT,

  -- Activity tracking
  last_seen_at    TIMESTAMPTZ,

  -- User preferences (notification settings, UI prefs, theme overrides, etc.)
  preferences     JSONB           NOT NULL  DEFAULT '{}'::jsonb,

  -- Soft-delete support
  deleted_at      TIMESTAMPTZ,

  -- Standard timestamps
  created_at      TIMESTAMPTZ     NOT NULL  DEFAULT NOW(),
  updated_at      TIMESTAMPTZ     NOT NULL  DEFAULT NOW(),

  -- Constraints
  CONSTRAINT users_email_format
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
  CONSTRAINT users_full_name_length
    CHECK (full_name IS NULL OR char_length(full_name) BETWEEN 1 AND 120)
);

COMMENT ON TABLE  public.users                  IS 'Application user profiles linked 1:1 with auth.users.';
COMMENT ON COLUMN public.users.id               IS 'UUID, foreign key to auth.users.id (1:1).';
COMMENT ON COLUMN public.users.organization_id  IS 'Organization this user belongs to.';
COMMENT ON COLUMN public.users.email            IS 'Cached email address (kept in sync with auth.users).';
COMMENT ON COLUMN public.users.full_name        IS 'Display name shown in UI.';
COMMENT ON COLUMN public.users.role             IS 'Permission tier: owner, admin, analyst, viewer.';
COMMENT ON COLUMN public.users.status           IS 'Lifecycle status: invited, active, disabled.';
COMMENT ON COLUMN public.users.avatar_url       IS 'Profile picture URL.';
COMMENT ON COLUMN public.users.last_seen_at     IS 'Timestamp of most recent user activity.';
COMMENT ON COLUMN public.users.preferences      IS 'User-specific preferences (notifications, UI, etc.) as JSONB.';
COMMENT ON COLUMN public.users.deleted_at       IS 'Soft-delete timestamp (NULL = active).';


-- Most queries scope to a specific organization — heavily used.
CREATE INDEX IF NOT EXISTS idx_users_organization_id
  ON public.users(organization_id)
  WHERE deleted_at IS NULL;

-- Unique email per organization (no duplicate seats in the same org).
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_org_email_unique
  ON public.users(organization_id, lower(email))
  WHERE deleted_at IS NULL;

-- Status filtering (active vs invited dashboards).
CREATE INDEX IF NOT EXISTS idx_users_status
  ON public.users(status)
  WHERE deleted_at IS NULL;

-- Activity heatmaps and "online now" queries.
CREATE INDEX IF NOT EXISTS idx_users_last_seen_at
  ON public.users(last_seen_at DESC NULLS LAST)
  WHERE deleted_at IS NULL;


DROP TRIGGER IF EXISTS set_users_updated_at ON public.users;

CREATE TRIGGER set_users_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_updated_at();


CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  INSERT INTO public.users (
    id,
    email,
    full_name,
    organization_id,
    status
  )
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data ->> 'full_name', NULL),
    NULLIF(NEW.raw_user_meta_data ->> 'organization_id', '')::uuid,
    'active'
  )
  ON CONFLICT (id) DO NOTHING;

  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.handle_new_auth_user() IS
  'Auto-creates a public.users profile row whenever a new auth.users row is created.';

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_auth_user();


ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
