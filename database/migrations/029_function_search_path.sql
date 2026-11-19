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
ALTER FUNCTION public.claim_jobs(text, integer, integer, text[])                    SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.generate_short_id(text)                                       SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.handle_updated_at()                                           SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.normalize_ioc_value()                                         SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.prevent_audit_log_mutation()                                  SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.purge_behavior(integer, integer)                              SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.purge_correlation_ledger(integer)                             SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.purge_expired(integer, integer, integer, integer)             SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.recompute_memory_decay_score()                                SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.search_agent_memory(uuid, vector, integer, numeric, memory_type) SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.set_incident_status_timestamps()                              SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.set_threat_resolved_at()                                      SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.update_agent_stats_on_insert()                                SET search_path = public, extensions, pg_temp;
ALTER FUNCTION public.update_agent_stats_on_run()                                   SET search_path = public, extensions, pg_temp;
