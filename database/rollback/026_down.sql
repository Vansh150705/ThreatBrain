-- 026_down.sql: DESTRUCTIVE rollback of 026_correlation_ledger.sql (drops the correlation de-duplication ledger).
-- After rolling back, run the application version that predates the ledger, or correlations may be reported twice.
begin;
drop function if exists public.purge_correlation_ledger(integer);
drop table if exists public.correlation_hits cascade;
delete from public.schema_migrations where filename = '026_correlation_ledger.sql';
commit;
