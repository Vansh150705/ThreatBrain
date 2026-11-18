-- 027_down.sql: DESTRUCTIVE rollback of 027_behavior_analytics.sql (drops every behavioural baseline, anomaly record,
-- setting and suppression). Baselines can be rebuilt from stored events (POST /behavior/learn) but analyst dispositions
-- and suppressions cannot. Take a backup first (database/backup.sh).
begin;
drop function if exists public.purge_behavior(integer, integer);
drop table if exists public.behavior_suppressions cascade;
drop table if exists public.behavior_settings cascade;
drop table if exists public.behavior_anomalies cascade;
drop table if exists public.behavior_profiles cascade;
delete from public.schema_migrations where filename = '027_behavior_analytics.sql';
commit;
