#!/usr/bin/env bash
# Database-level security properties on a REAL PostgreSQL server, against a fully migrated scratch database
# (default tb_migration_check, created by ../verify_migrations.sh):
#   * every public table has row level security enabled
#   * tables that must never be visible to end-user roles (secrets, queue, ledgers) have no policy granting access
#   * audit_logs is append-only even for a superuser-less owner (trigger), and TRUNCATE is blocked for non-owners
#   * the end-user roles (anon / authenticated) cannot read other tenants' rows or any secret table
#   PGHOST=... PGPORT=... PGUSER=... ./database/tests/test_security.sh [db]
set -uo pipefail
DB="${1:-tb_migration_check}"
Q() { psql -v ON_ERROR_STOP=1 -At -q "$DB" -c "$1"; }
pass=0; fail=0
ok()  { echo "ok   $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

no_rls="$(Q "select string_agg(c.relname, ', ') from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' and not c.relrowsecurity")"
check "RLS is enabled on every public table (missing: ${no_rls:-none})" "[ -z '$no_rls' ]"

SECRET="api_keys jobs replay_guard worker_heartbeats correlation_hits schema_migrations detection_rule_versions rule_overrides pipeline_runs"
for t in $SECRET; do
  exists="$(Q "select to_regclass('public.$t') is not null")"; [ "$exists" = t ] || continue
  pol="$(Q "select count(*) from pg_policies where schemaname='public' and tablename='$t'")"
  check "no RLS policy exposes $t to end-user roles" "[ '$pol' = 0 ]"
done

# --- behaviour as the end-user roles
Q "insert into public.organizations(name, slug) values ('sec-a','sec-a'),('sec-b','sec-b') on conflict do nothing" >/dev/null
A=$(Q "select id from public.organizations where slug='sec-a'"); B=$(Q "select id from public.organizations where slug='sec-b'")
Q "insert into public.api_keys(organization_id, name, key_prefix, key_hash, scopes) values ('$A','k','tbk_x','h$RANDOM$RANDOM',array['ingest'])" >/dev/null
Q "insert into public.jobs(organization_id, kind) values ('$A','t')" >/dev/null

for role in anon authenticated; do
  for t in api_keys jobs replay_guard; do
    out="$(psql -At -q "$DB" -c "set role $role; select count(*) from public.$t" 2>&1)"
    check "$role cannot read $t (got: ${out##*: })" "[ \"\$out\" = 0 ] || grep -qi 'permission denied' <<<\"\$out\""
  done
done
out="$(psql -At -q "$DB" -c "set role anon; select count(*) from public.threats" 2>&1)"
check "anon sees no threats" "[ \"\$out\" = 0 ] || grep -qi 'permission denied' <<<\"\$out\""

# a user of org A must not see org B's rows (policy uses auth.uid() -> users.organization_id)
EMAIL="a$RANDOM$RANDOM@sec.test"
UA=$(Q "insert into auth.users(id, email) values (gen_random_uuid(), '$EMAIL') returning id")
[ -n "$UA" ] || { echo 'FAIL could not create test user'; exit 1; }
# the signup trigger already created the profile row for the new auth user; attach it to org A
Q "update public.users set organization_id='$A', role='analyst', status='active' where id='$UA'" >/dev/null 2>&1
Q "delete from public.threats where title in ('mine','theirs')" >/dev/null 2>&1
Q "insert into public.threats(organization_id, title, severity, status) values ('$A','mine','low','open'),('$B','theirs','low','open')" >/dev/null 2>&1
seen="$(psql -At -q "$DB" -c "set role authenticated; select set_config('request.jwt.claim.sub','$UA',false); select string_agg(title, ',') from public.threats" 2>&1 | tail -1)"
check "authenticated org-A user sees only org-A threats (saw: $seen)" "[ '$seen' = mine ]"

# --- audit immutability
Q "insert into public.audit_logs(organization_id, actor_type, action, target_type) values ('$A','system','sec.test','test')" >/dev/null 2>&1
upd="$(psql -At -q "$DB" -c "update public.audit_logs set action='tampered'" 2>&1)"
check "audit_logs UPDATE is blocked" "grep -qi 'append-only' <<<\"\$upd\""
del="$(psql -At -q "$DB" -c "delete from public.audit_logs" 2>&1)"
check "audit_logs DELETE is blocked" "grep -qi 'append-only' <<<\"\$del\""
for role in anon authenticated; do
  tr="$(psql -At -q "$DB" -c "set role $role; truncate public.audit_logs" 2>&1)"
  check "$role cannot TRUNCATE audit_logs" "grep -qi 'permission denied\|must be owner' <<<\"\$tr\""
done
echo "---- $pass passed, $fail failed"; exit $fail
