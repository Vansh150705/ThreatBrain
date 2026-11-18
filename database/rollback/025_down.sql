-- 025_down.sql: DESTRUCTIVE manual rollback of 025_enterprise_platform.sql.
--
-- Prefer rolling the APPLICATION back and restoring from a backup (docs/OPERATIONS.md): this script drops
-- the durable queue, the event-store extensions, custom detection rules and their versions, and rule overrides.
-- It does NOT remove enum values added by 022/024 (PostgreSQL cannot drop them) and does NOT restore IOC rows that
-- 025 removed when it tightened the unique index.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f database/rollback/025_down.sql
begin;
-- restore 023's organization trigger function BEFORE dropping the helper it no longer calls
create or replace function public.handle_new_organization() returns trigger language plpgsql security definer set search_path = public as $$
begin
  perform public.seed_default_agents_for_org(new.id);
  perform public.seed_log_analysis_agent(new.id);
  return new;
end;
$$;
drop function if exists public.purge_expired(integer, integer, integer, integer);
drop function if exists public.claim_jobs(text, integer, integer, text[]);
drop function if exists public.seed_enterprise_agents(uuid);
delete from public.agents where agent_key::text = 'detection_engineering';
drop table if exists public.threat_events cascade;
drop table if exists public.jobs cascade;
drop table if exists public.worker_heartbeats cascade;
drop table if exists public.detection_rule_versions cascade;
drop table if exists public.detection_rules cascade;
drop table if exists public.rule_overrides cascade;
drop table if exists public.replay_guard cascade;
alter table public.api_keys drop column if exists require_signature, drop column if exists last_used_ip,
  drop column if exists rotated_from, drop column if exists use_count;
drop index if exists public.uq_events_org_idempotency;
drop index if exists public.idx_events_org_srcip_time, public.idx_events_org_user_time, public.idx_events_org_asset_time, public.idx_events_org_retention;
alter table public.events drop column if exists asset_name, drop column if exists source_system, drop column if exists outcome,
  drop column if exists idempotency_key, drop column if exists mitre_tactics, drop column if exists mitre_techniques,
  drop column if exists detections, drop column if exists alerted;
drop index if exists public.idx_iocs_org_type_value_unique;
create unique index if not exists idx_iocs_org_type_value_unique on public.iocs(organization_id, ioc_type, normalized_value) where deleted_at is null;
delete from public.schema_migrations where filename = '025_enterprise_platform.sql';
commit;
