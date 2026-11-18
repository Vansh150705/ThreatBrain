#!/usr/bin/env bash
# Applies every migration (and the demo seed) to a SCRATCH PostgreSQL database to
# prove the SQL is valid on a fresh install. It creates minimal stand-ins for the
# parts of Supabase the schema relies on (roles, auth schema, extensions schema),
# so it runs on a plain PostgreSQL 14+ server.
#
#   PGHOST=localhost PGPORT=5432 PGUSER=postgres ./verify_migrations.sh [scratch_db_name]
#
# WARNING: drops and recreates the scratch database (default: tb_migration_check).
# pgvector is swapped for float4[] (and its ANN index skipped) if not installed.
set -euo pipefail
DB="${1:-tb_migration_check}"
HERE="$(cd "$(dirname "$0")" && pwd)"
P=(psql -v ON_ERROR_STOP=1 -q)

"${P[@]}" postgres -c "drop database if exists \"$DB\"" -c "create database \"$DB\""
"${P[@]}" "$DB" <<'SQL'
do $$ begin
 if not exists (select from pg_roles where rolname='anon') then create role anon nologin; end if;
 if not exists (select from pg_roles where rolname='authenticated') then create role authenticated nologin; end if;
 if not exists (select from pg_roles where rolname='service_role') then create role service_role nologin bypassrls; end if;
end $$;
create schema if not exists auth; create schema if not exists extensions;
create table if not exists auth.users (id uuid primary key default gen_random_uuid(), email text, raw_user_meta_data jsonb default '{}');
create or replace function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('request.jwt.claim.sub', true),'')::uuid $$;
create or replace function auth.jwt() returns jsonb language sql stable as $$ select coalesce(nullif(current_setting('request.jwt.claims', true),''),'{}')::jsonb $$;
create extension if not exists "uuid-ossp" schema extensions;
create extension if not exists pgcrypto schema extensions;
SQL

HAS_VECTOR=$("${P[@]}" -At postgres -c "select count(*) from pg_available_extensions where name='vector'")
fail=0
# 022 must be its own psql session (new enum value); each file here is one session.
for f in "$HERE"/migrations/0*.sql "$HERE"/seeders/001_demo_data.sql; do
  if [ "$HAS_VECTOR" = "0" ]; then
    src=$(python3 - "$f" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
s = re.sub(r'extensions\.vector\(\d+\)', 'float4[]', s)
s = re.sub(r'CREATE EXTENSION[^;]*vector[^;]*;', '', s, flags=re.I)
s = re.sub(r'CREATE INDEX IF NOT EXISTS \w+\s+ON public\.agent_memory[^;]*USING hnsw[^;]*;', '', s, flags=re.I | re.S)
print(s)
PY
)
  else
    src=$(cat "$f")
  fi
  if err=$("${P[@]}" "$DB" <<<"$src" 2>&1 | grep -E "ERROR|FATAL" | head -3) && [ -n "$err" ]; then
    echo "FAIL $(basename "$f"): $err"; fail=1
  else
    echo "ok   $(basename "$f")"
  fi
done
exit $fail
