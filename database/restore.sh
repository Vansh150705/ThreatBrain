#!/usr/bin/env bash
# Restore the DATA from a backup.sh dump into an existing ThreatBrain database, atomically.
#
#   DATABASE_URL=postgresql://... ./restore.sh FILE.dump --yes
#
# How: the schema must already exist (run ./migrate.sh first; on a brand-new Supabase project that creates it).
# This script then, inside ONE transaction, TRUNCATEs every public table and loads the dump's data (including the
# schema_migrations ledger, so it reflects the dump's schema level; run ./migrate.sh afterwards to roll an older dump forward). If anything fails the transaction rolls back and the existing data is untouched.
#
# DESTRUCTIVE: all current application data is replaced by the backup. Refuses without --yes, verifies the dump checksum
# when FILE.dump.sha256 exists. Stop the API and workers before restoring and start them after, then run
# `python -m app.doctor`. auth.users (Supabase Auth) is not touched; rows in public.users must match existing auth users.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
FILE="${1:?usage: restore.sh FILE.dump --yes}"
[ "${2:-}" = "--yes" ] || { echo "refusing: restore replaces ALL application data in the target database. Re-run with --yes after stopping the API/workers." >&2; exit 2; }
if [ -f "$FILE.sha256" ]; then (cd "$(dirname "$FILE")" && sha256sum -c "$(basename "$FILE").sha256" >/dev/null) || { echo "checksum mismatch; not restoring" >&2; exit 3; }; fi
TABLES="$(psql "$DATABASE_URL" -X -At -c "select string_agg(format('public.%I', tablename), ', ') from pg_tables where schemaname='public'")"
# session_replication_role=replica lets tables load in any order despite foreign keys (the same setting the
# Supabase CLI uses for data dumps). It needs the privilege to set it (superuser; on Supabase use the `postgres` role).
# If the role lacks it the statement fails, the transaction rolls back and no data is changed.
{
  echo "set session_replication_role = replica;"
  echo "truncate table $TABLES restart identity cascade;"
  pg_restore --data-only --no-owner --no-privileges -f - "$FILE"
} | psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 --single-transaction -o /dev/null
echo "restored data from $FILE"
