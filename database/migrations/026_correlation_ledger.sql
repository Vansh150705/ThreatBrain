-- 026_correlation_ledger.sql
-- Correlation completions are detected independently by whichever worker processes the last-arriving event,
-- so two workers can both see the same completed pattern. The ledger makes reporting exactly-once:
-- the worker whose INSERT wins reports the correlation; the other sees a conflict and stays silent.
CREATE TABLE IF NOT EXISTS public.correlation_hits (
  organization_id  UUID        NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  dedupe_key       TEXT        NOT NULL,               -- "<correlation id>:<group value>:<final event id | window bucket>"
  correlation_id   TEXT        NOT NULL,
  event_id         UUID        REFERENCES public.events(id) ON DELETE SET NULL,   -- the event whose processing reported it
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (organization_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_correlation_hits_created ON public.correlation_hits(created_at);
ALTER TABLE public.correlation_hits ENABLE ROW LEVEL SECURITY;
GRANT ALL PRIVILEGES ON public.correlation_hits TO service_role;

-- retention: ledger rows only need to outlive the longest correlation window (24h); keep a week.
CREATE OR REPLACE FUNCTION public.purge_correlation_ledger(p_days INTEGER DEFAULT 7)
RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE n BIGINT;
BEGIN
  DELETE FROM public.correlation_hits WHERE created_at < NOW() - make_interval(days => p_days);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END;
$$;
GRANT EXECUTE ON FUNCTION public.purge_correlation_ledger(INTEGER) TO service_role;
