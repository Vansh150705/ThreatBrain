-- 027_behavior_analytics.sql
-- Behavioural analytics (UEBA): per-tenant baselines, scored anomalies with explanations, tunable settings and suppressions.
--
-- Security model
--  * behavior_profiles / behavior_suppressions / behavior_settings: RLS enabled and NO policy for end users -> only the
--    backend (service role) can read or write baselines. A baseline is a statistical summary of what an account or host
--    normally does (hosts reached, source networks, hours, process names, byte-volume quantiles); it never stores
--    command lines, payloads or secrets.
--  * behavior_anomalies: analysts and above of the SAME organisation may read (the same boundary as threats); only the
--    backend writes.
--  * Every table is keyed by organization_id, deleted with the organisation, and covered by retention (purge_behavior).
CREATE TABLE IF NOT EXISTS public.behavior_profiles (
  organization_id  UUID        NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  entity_type      TEXT        NOT NULL CHECK (entity_type IN ('user', 'host', 'population')),
  entity_id        TEXT        NOT NULL CHECK (char_length(entity_id) BETWEEN 1 AND 256),
  state            JSONB       NOT NULL DEFAULT '{}'::jsonb,
  version          INTEGER     NOT NULL DEFAULT 1,           -- optimistic concurrency: writers compare-and-swap on this
  event_count      BIGINT      NOT NULL DEFAULT 0,
  first_seen       TIMESTAMPTZ,
  last_seen        TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (organization_id, entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_seen ON public.behavior_profiles(last_seen);
ALTER TABLE public.behavior_profiles ENABLE ROW LEVEL SECURITY;
COMMENT ON TABLE public.behavior_profiles IS 'Per-entity behavioural baselines (service role only). state is bounded by the application (see app/behavior/model.py).';

CREATE TABLE IF NOT EXISTS public.behavior_anomalies (
  id                UUID        PRIMARY KEY DEFAULT extensions.uuid_generate_v4(),
  organization_id   UUID        NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  entity_type       TEXT        NOT NULL CHECK (entity_type IN ('user', 'host')),
  entity_id         TEXT        NOT NULL,
  event_id          UUID        REFERENCES public.events(id) ON DELETE SET NULL,
  feature           TEXT        NOT NULL,                    -- e.g. auth.source_net, net.bytes_out_hour
  value_key         TEXT        NOT NULL DEFAULT '',         -- the novel value / bucket, if categorical
  score             REAL        NOT NULL CHECK (score >= 0 AND score <= 1),
  severity          TEXT        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  explanation       JSONB       NOT NULL DEFAULT '{}'::jsonb, -- observed vs expected, baseline maturity, peer prevalence, method
  alerted           BOOLEAN     NOT NULL DEFAULT FALSE,       -- true when it (alone or combined) produced a detection
  suppressed_reason TEXT,                                     -- set when it was withheld: budget | cooldown | suppression | learning
  disposition       TEXT        NOT NULL DEFAULT 'open' CHECK (disposition IN ('open', 'confirmed', 'benign', 'expected')),
  disposition_by    UUID        REFERENCES public.users(id) ON DELETE SET NULL,
  disposition_at    TIMESTAMPTZ,
  observed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_behavior_anomalies_org_time ON public.behavior_anomalies(organization_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_behavior_anomalies_entity ON public.behavior_anomalies(organization_id, entity_type, entity_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_behavior_anomalies_alerted ON public.behavior_anomalies(organization_id, alerted, observed_at DESC);
ALTER TABLE public.behavior_anomalies ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "behavior_anomalies_select" ON public.behavior_anomalies;
CREATE POLICY "behavior_anomalies_select" ON public.behavior_anomalies
  FOR SELECT TO authenticated
  USING (public.is_org_member(organization_id) AND public.is_at_least_analyst());

CREATE TABLE IF NOT EXISTS public.behavior_settings (
  organization_id  UUID        PRIMARY KEY REFERENCES public.organizations(id) ON DELETE CASCADE,
  enabled          BOOLEAN     NOT NULL DEFAULT TRUE,
  sensitivity      TEXT        NOT NULL DEFAULT 'balanced' CHECK (sensitivity IN ('low', 'balanced', 'high')),
  params           JSONB       NOT NULL DEFAULT '{}'::jsonb,  -- validated overrides, see app/behavior/config.py
  updated_by       UUID        REFERENCES public.users(id) ON DELETE SET NULL,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE public.behavior_settings ENABLE ROW LEVEL SECURITY;

CREATE TABLE IF NOT EXISTS public.behavior_suppressions (
  id               UUID        PRIMARY KEY DEFAULT extensions.uuid_generate_v4(),
  organization_id  UUID        NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  entity_type      TEXT        NOT NULL DEFAULT '*',
  entity_id        TEXT        NOT NULL DEFAULT '*',
  feature          TEXT        NOT NULL DEFAULT '*',
  value_key        TEXT        NOT NULL DEFAULT '*',
  reason           TEXT        NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
  created_by       UUID        REFERENCES public.users(id) ON DELETE SET NULL,
  expires_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_behavior_suppressions_org ON public.behavior_suppressions(organization_id);
ALTER TABLE public.behavior_suppressions ENABLE ROW LEVEL SECURITY;

-- Retention: anomalies are evidence and kept 90 days by default; baselines of entities not seen for 180 days are dropped
-- (an account that left, a decommissioned host). Called by the maintenance job.
CREATE OR REPLACE FUNCTION public.purge_behavior(p_anomaly_days INTEGER DEFAULT 90, p_profile_days INTEGER DEFAULT 180)
RETURNS JSONB LANGUAGE plpgsql AS $$
DECLARE n_anom BIGINT; n_prof BIGINT;
BEGIN
  DELETE FROM public.behavior_anomalies WHERE created_at < NOW() - make_interval(days => p_anomaly_days);
  GET DIAGNOSTICS n_anom = ROW_COUNT;
  DELETE FROM public.behavior_profiles
   WHERE entity_type <> 'population' AND last_seen < NOW() - make_interval(days => p_profile_days);
  GET DIAGNOSTICS n_prof = ROW_COUNT;
  DELETE FROM public.behavior_suppressions WHERE expires_at IS NOT NULL AND expires_at < NOW() - INTERVAL '30 days';
  RETURN jsonb_build_object('behavior_anomalies', n_anom, 'behavior_profiles', n_prof);
END;
$$;

GRANT ALL PRIVILEGES ON public.behavior_profiles, public.behavior_anomalies, public.behavior_settings,
  public.behavior_suppressions TO service_role;
GRANT SELECT ON public.behavior_anomalies TO authenticated;
GRANT EXECUTE ON FUNCTION public.purge_behavior(INTEGER, INTEGER) TO service_role;
