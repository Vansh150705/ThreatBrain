CREATE EXTENSION IF NOT EXISTS "uuid-ossp"   WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS "pgcrypto"    WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS "vector"      WITH SCHEMA extensions;


CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.handle_updated_at() IS
  'Trigger function that sets updated_at to NOW() before any row UPDATE.';


CREATE OR REPLACE FUNCTION public.generate_short_id(prefix TEXT)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  random_part TEXT;
BEGIN
  -- 3 random bytes → 6 hex characters, uppercased for readability
  random_part := UPPER(ENCODE(extensions.gen_random_bytes(3), 'hex'));
  RETURN prefix || '-' || random_part;
END;
$$;

COMMENT ON FUNCTION public.generate_short_id(TEXT) IS
  'Generates a human-friendly short ID like INC-A3F2B9 with the given prefix.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'severity_level') THEN
    CREATE TYPE public.severity_level AS ENUM (
      'info',
      'low',
      'medium',
      'high',
      'critical'
    );
  END IF;
END$$;

COMMENT ON TYPE public.severity_level IS
  'Standard severity classification for events, threats, and incidents.';


DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'status_level') THEN
    CREATE TYPE public.status_level AS ENUM (
      'open',
      'investigating',
      'contained',
      'resolved',
      'closed',
      'false_positive'
    );
  END IF;
END$$;

COMMENT ON TYPE public.status_level IS
  'Lifecycle status for incidents, threats, and agent runs.';

