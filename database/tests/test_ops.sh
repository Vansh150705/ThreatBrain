#!/usr/bin/env bash
# Operational SQL/script tests on a REAL PostgreSQL server: migrate.sh (apply, idempotency, drift refusal,
# concurrent runners, baseline), 025 rollback, backup + strict verify + atomic restore.
#   PGHOST=... PGPORT=... PGUSER=... ./database/tests/test_ops.sh        (needs createdb rights; uses scratch DBs tb_ops_*)
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
export MIGRATE_NO_VECTOR="${MIGRATE_NO_VECTOR:-1}"
BASE_URL() { echo "postgresql:///$1?host=${PGHOST:-/var/run/postgresql}&port=${PGPORT:-5432}&user=${PGUSER:-postgres}"; }
pass=0; fail=0
ok()  { echo "ok   $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

PREP='
do $$ begin
 if not exists (select from pg_roles where rolname='"'"'anon'"'"') then create role anon nologin; end if;
 if not exists (select from pg_roles where rolname='"'"'authenticated'"'"') then create role authenticated nologin; end if;
 if not exists (select from pg_roles where rolname='"'"'service_role'"'"') then create role service_role nologin bypassrls; end if;
end $$;
create schema if not exists auth; create schema if not exists extensions;
create table if not exists auth.users (id uuid primary key default gen_random_uuid(), email text, raw_user_meta_data jsonb default '"'"'{}'"'"');
create or replace function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('"'"'request.jwt.claim.sub'"'"', true),'"'"''"'"')::uuid $$;
create or replace function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('"'"'request.jwt.claims'"'"', true),'"'"''"'"'),'"'"'{}'"'"')::jsonb $$;
create extension if not exists "uuid-ossp" schema extensions;
create extension if not exists pgcrypto schema extensions;'
newdb() { psql "$(BASE_URL postgres)" -X -q -c "drop database if exists $1" -c "create database $1" 2>/dev/null; psql "$(BASE_URL "$1")" -X -q -c "$PREP" >/dev/null 2>&1; }
q() { psql "$(BASE_URL "$1")" -X -At -c "$2"; }
cleanup() { for d in tb_ops_a tb_ops_c tb_ops_b tb_ops_v; do psql "$(BASE_URL postgres)" -X -q -c "drop database if exists $d" 2>/dev/null; done; }
trap cleanup EXIT

# ---- apply / idempotent / status
newdb tb_ops_a; export DATABASE_URL="$(BASE_URL tb_ops_a)"
n=$("$HERE/migrate.sh" 2>&1 | grep -c '^applying')
check "fresh database: every migration applies ($n files)" "[ $n -eq $(ls "$HERE"/migrations/0*.sql | wc -l) ]"
check "re-run applies nothing" "[ \"\$($HERE/migrate.sh 2>&1 | grep -c '^applying')\" = 0 ]"
check "--status reports up to date" "$HERE/migrate.sh --status 2>&1 | grep -q 'up to date'"

# ---- drift refusal
tmp="$(mktemp -d)"; cp -r "$HERE/migrations" "$HERE/migrate.sh" "$tmp/"; echo "-- edited after apply" >> "$tmp/migrations/016_add_is_demo_org.sql"
"$tmp/migrate.sh" >/dev/null 2>&1; rc=$?
check "edited-after-apply migration is refused (exit 3)" "[ $rc -eq 3 ]"
out="$("$tmp/migrate.sh" --status 2>&1)"; check "--status names the drifted file" "grep -q 'DRIFT.*016_add_is_demo_org' <<<\"\$out\""; rm -rf "$tmp"

# ---- concurrency
newdb tb_ops_c; export DATABASE_URL="$(BASE_URL tb_ops_c)"
( "$HERE/migrate.sh" > "$HERE/../.ops_a.log" 2>&1 & "$HERE/migrate.sh" > "$HERE/../.ops_b.log" 2>&1 & wait )
a=$(grep -c '^applying' "$HERE/../.ops_a.log"); b=$(grep -c '^applying' "$HERE/../.ops_b.log"); rm -f "$HERE/../.ops_a.log" "$HERE/../.ops_b.log"
total=$(ls "$HERE"/migrations/0*.sql | wc -l)
check "two concurrent runners apply each file exactly once ($a + $b of $total)" "[ $((a+b)) -eq $total ]"
check "ledger has one row per file" "[ \"\$(q tb_ops_c 'select count(distinct filename) from public.schema_migrations')\" = $total ]"

# ---- baseline
export DATABASE_URL="$(BASE_URL tb_ops_a)"; q tb_ops_a "delete from public.schema_migrations" >/dev/null
"$HERE/migrate.sh" --baseline 023 >/dev/null 2>&1
check "baseline records 001..023 without running them" "[ \"\$(q tb_ops_a 'select count(*) from public.schema_migrations')\" = 23 ]"
out="$("$HERE/migrate.sh" --dry-run 2>&1)"; check "baseline leaves 024+ pending" "grep -q '^pending   024' <<<\"\$out\""
"$HERE/migrate.sh" >/dev/null 2>&1
check "pending migrations then apply on top of a baseline" "[ \"\$(q tb_ops_a 'select count(*) from public.schema_migrations')\" = $total ]"

# ---- rollback of 025
q tb_ops_a "insert into public.organizations(name, slug) values ('o1','o1')" >/dev/null
psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 -f "$HERE/rollback/025_down.sql" >/dev/null 2>&1; rc=$?
check "025_down.sql runs" "[ $rc -eq 0 ]"
check "025 objects are gone" "[ \"\$(q tb_ops_a \"select coalesce(to_regclass('public.jobs')::text,'') || coalesce(to_regclass('public.detection_rules')::text,'')\")\" = '' ]"
q tb_ops_a "insert into public.organizations(name, slug) values ('o2','o2')" >/dev/null 2>&1
check "new organizations still work after rollback (trigger restored)" "[ \"\$(q tb_ops_a \"select count(*) from public.agents where organization_id=(select id from public.organizations where slug='o2')\")\" = 8 ]"
"$HERE/migrate.sh" >/dev/null 2>&1
check "025 re-applies after rollback" "[ \"\$(q tb_ops_a \"select to_regclass('public.jobs') is not null\")\" = t ]"

# ---- rollback of 027 (drops behavioural baselines; re-applies cleanly)
q tb_ops_a "insert into public.behavior_settings(organization_id, sensitivity) select id, 'high' from public.organizations limit 1" >/dev/null
psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 -f "$HERE/rollback/027_down.sql" >/dev/null 2>&1; rc=$?
check "027_down.sql runs" "[ $rc -eq 0 ]"
check "027 objects are gone and the ledger forgets it" "[ \"\$(q tb_ops_a \"select coalesce(to_regclass('public.behavior_profiles')::text,'') || coalesce(to_regclass('public.behavior_anomalies')::text,'')\")\" = '' ] && [ \"\$(q tb_ops_a \"select count(*) from public.schema_migrations where filename like '027%'\")\" = 0 ]"
"$HERE/migrate.sh" >/dev/null 2>&1
check "027 re-applies after rollback" "[ \"\$(q tb_ops_a \"select to_regclass('public.behavior_profiles') is not null\")\" = t ]"

# ---- backup / strict verify / atomic restore
q tb_ops_a "truncate public.organizations cascade" >/dev/null 2>&1
psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 -f "$HERE/seeders/001_demo_data.sql" >/dev/null 2>&1
t0=$(q tb_ops_a "select count(*) from public.threats")
check "demo seed loaded ($t0 threats)" "[ $t0 -gt 0 ]"
bdir="$(mktemp -d)"; "$HERE/backup.sh" "$bdir" >/dev/null 2>&1; dump="$(ls "$bdir"/*.dump)"
check "backup written with checksum" "[ -s '$dump' ] && [ -s '$dump.sha256' ]"
printf '%s' "$PREP" > "$bdir/prep.sql"
out="$(VERIFY_PREPARE_SQL="$bdir/prep.sql" VERIFY_ADMIN_URL="$(BASE_URL postgres)" "$HERE/backup.sh" --verify "$dump" 2>&1)"
check "backup verify (restore into scratch DB, compare counts)" "grep -q 'backup verified' <<<\"\$out\""
q tb_ops_a "truncate public.events, public.threats cascade" >/dev/null 2>&1
check "data loss simulated" "[ \"\$(q tb_ops_a 'select count(*) from public.threats')\" = 0 ]"
"$HERE/restore.sh" "$dump" >/dev/null 2>&1; check "restore refuses without --yes" "[ $? -eq 2 ]"
"$HERE/restore.sh" "$dump" --yes >/dev/null 2>&1
check "restore brings the data back" "[ \"\$(q tb_ops_a 'select count(*) from public.threats')\" = $t0 ]"
q tb_ops_a "alter table public.worker_heartbeats rename to wh_tmp" >/dev/null; before=$(q tb_ops_a "select count(*) from public.users")
q tb_ops_a "delete from public.threats" >/dev/null 2>&1; mid=$(q tb_ops_a "select count(*) from public.threats")
"$HERE/restore.sh" "$dump" --yes >/dev/null 2>&1; rc=$?
check "restore into a mismatched schema fails (exit $rc)" "[ $rc -ne 0 ]"
check "failed restore changed nothing" "[ \"\$(q tb_ops_a 'select count(*) from public.threats')\" = $mid ]"
q tb_ops_a "alter table public.wh_tmp rename to worker_heartbeats" >/dev/null
printf 'x' >> "$dump"; "$HERE/restore.sh" "$dump" --yes >/dev/null 2>&1
check "tampered dump is refused by checksum (exit 3)" "[ $? -eq 3 ]"; rm -rf "$bdir"

echo "---- $pass passed, $fail failed"; exit $fail
