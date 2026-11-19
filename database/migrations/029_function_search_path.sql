-- 029_function_search_path.sql
-- Supabase's security advisor (lint 0011, function_search_path_mutable) flags functions that do not pin a search_path:
-- they resolve unqualified names through whatever the caller's session has set, which lets a caller who can create
-- objects in an earlier schema shadow the ones the function means to use.
--
-- Pin it on the 14 functions flagged. All of them are SECURITY INVOKER, so this changes name resolution only, not the
-- privileges they run with. The path is "public, extensions, pg_temp", not just "public": pgvector (the vector type and
-- the <=> operator), pgcrypto and uuid-ossp are installed in the "extensions" schema, so search_agent_memory and any
-- function using gen_random_bytes()/uuid helpers would stop resolving them with "public" alone. pg_temp goes last so
-- temporary objects cannot shadow real ones. Idempotent: re-running just re-applies the same setting.
-- The functions are looked up by name rather than by full signature: search_agent_memory takes a pgvector argument, and on a
-- database without pgvector that signature cannot even be parsed. Each of these names has a single overload; any function that
-- does not exist on this database is skipped.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.prokind = 'f'
       AND p.proname = ANY (ARRAY[
         'claim_jobs',
         'generate_short_id',
         'handle_updated_at',
         'normalize_ioc_value',
         'prevent_audit_log_mutation',
         'purge_behavior',
         'purge_correlation_ledger',
         'purge_expired',
         'recompute_memory_decay_score',
         'search_agent_memory',
         'set_incident_status_timestamps',
         'set_threat_resolved_at',
         'update_agent_stats_on_insert',
         'update_agent_stats_on_run'
       ])
  LOOP
    EXECUTE format('ALTER FUNCTION %s SET search_path = public, extensions, pg_temp', r.sig);
  END LOOP;
END $$;
