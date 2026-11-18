-- 028_revoke_public_function_execute.sql
-- Supabase's security advisor (lint 0028/0029) flagged SECURITY DEFINER functions that anonymous and signed-in users
-- can call through /rest/v1/rpc/<name>. None of these is meant to be a public API:
--   * log_audit_event            would let any caller write audit rows for an arbitrary organisation
--   * seed_* / handle_new_*      would let any caller seed agents/playbooks for an arbitrary organisation
--   * rls_auto_enable            event-trigger helper
-- They are invoked by the backend with the service role (audit, seeding) or by triggers, which do not check EXECUTE at
-- fire time. The RLS helper functions (is_org_member, is_at_least_*, is_owner, current_user_*) are deliberately NOT
-- touched: policies evaluate them as the signed-in role. Idempotent.
REVOKE EXECUTE ON FUNCTION public.log_audit_event(UUID, public.actor_type, TEXT, UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT,
  public.severity_level, public.audit_status, JSONB, JSONB, JSONB, TEXT, INET, TEXT, TEXT, UUID, JSONB, TEXT[])
  FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.seed_default_agents_for_org(UUID)    FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.seed_default_playbooks_for_org(UUID) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.seed_log_analysis_agent(UUID)        FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.seed_enterprise_agents(UUID)         FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_new_organization()            FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.handle_new_auth_user()               FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable()                    FROM PUBLIC, anon, authenticated;

-- the backend (service role) keeps access
GRANT EXECUTE ON FUNCTION public.log_audit_event(UUID, public.actor_type, TEXT, UUID, TEXT, TEXT, TEXT, UUID, TEXT, TEXT,
  public.severity_level, public.audit_status, JSONB, JSONB, JSONB, TEXT, INET, TEXT, TEXT, UUID, JSONB, TEXT[]) TO service_role;
GRANT EXECUTE ON FUNCTION public.seed_default_agents_for_org(UUID)    TO service_role;
GRANT EXECUTE ON FUNCTION public.seed_default_playbooks_for_org(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.seed_log_analysis_agent(UUID)        TO service_role;
GRANT EXECUTE ON FUNCTION public.seed_enterprise_agents(UUID)         TO service_role;
