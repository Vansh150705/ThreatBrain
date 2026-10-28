#!/usr/bin/env bash
# Logical backup of the application schema (public) in PostgreSQL custom format.
#
#   DATABASE_URL=postgresql://... ./backup.sh [output_dir]        -> <dir>/threatbrain-YYYYmmddTHHMMSSZ.dump (+ .sha256)
#   DATABASE_URL=postgresql://... ./backup.sh --verify FILE.dump  -> restores into a throw-away database and compares row counts
#
# Notes
#   * Supabase also takes its own physical backups / PITR (plan dependent); this is the portable, restorable-anywhere copy.
#   * The `auth` schema (user passwords, MFA, sessions) is owned by Supabase Auth and is NOT in this dump;
#     --verify needs VERIFY_PREPARE_SQL to create the auth stand-ins the schema references (public.users has a FK to auth.users);
#     restore it from Supabase's backups or users must reset their passwords.
#   * Secrets: API keys are stored hashed; signing secrets are derived from APP_SECRET (back that up in your secret manager).
#   * Retention: keep at least 7 daily + 4 weekly dumps, encrypt at rest, and run --verify on a schedule.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL}"
if [ "${1:-}" = "--verify" ]; then
  FILE="${2:?usage: backup.sh --verify FILE.dump}"
  SCRATCH="tb_verify_$(date +%s)"
  ADMIN_URL="${VERIFY_ADMIN_URL:-$DATABASE_URL}"          # needs CREATEDB; set VERIFY_ADMIN_URL to a maintenance database
  psql "$ADMIN_URL" -X -q -c "create database $SCRATCH" >/dev/null
  trap 'psql "$ADMIN_URL" -X -q -c "drop database if exists $SCRATCH" >/dev/null 2>&1 || true' EXIT
  SCRATCH_URL="$(python3 - "$ADMIN_URL" "$SCRATCH" <<'PY'
import re, sys
print(re.sub(r"^(postgres(?:ql)?://[^/]*/)[^?#]*", lambda m: m.group(1) + sys.argv[2], sys.argv[1]))
PY
)"
  [ -n "${VERIFY_PREPARE_SQL:-}" ] && psql "$SCRATCH_URL" -X -q -v ON_ERROR_STOP=1 -f "$VERIFY_PREPARE_SQL" >/dev/null
  # pre-data + data only: foreign keys to Supabase-owned auth.users cannot be validated in a scratch database
  pg_restore --section=pre-data --section=data --no-owner --no-privileges -d "$SCRATCH_URL" "$FILE" 2>/tmp/pg_restore_verify.log || true
  # the only benign message is the scratch database already having a `public` schema
  if grep -E "^pg_restore: error:" /tmp/pg_restore_verify.log | grep -v 'schema "public" already exists' | grep -q .; then
    echo "BACKUP VERIFICATION FAILED: restore reported errors:"; grep "^pg_restore: error:" /tmp/pg_restore_verify.log | grep -v 'schema "public" already exists' | head -5; exit 1
  fi
  count_sql="select string_agg(format('select %L as t, count(*) as n from public.%I', tablename, tablename), ' union all ' order by tablename) from pg_tables where schemaname='public'"
  q="$(psql "$DATABASE_URL" -X -At -c "$count_sql") order by 1"
  diff <(psql "$DATABASE_URL" -X -At -F' ' -c "$q") <(psql "$SCRATCH_URL" -X -At -F' ' -c "$q") \
    && echo "backup verified: schema objects and data restored; every public table has the same row count (constraints/indexes were not exercised)" \
    || { echo "BACKUP VERIFICATION FAILED: row counts differ (live data may have changed since the dump; re-run immediately after backup)"; exit 1; }
  exit 0
fi
OUT="${1:-.}"; mkdir -p "$OUT"
FILE="$OUT/threatbrain-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump "$DATABASE_URL" --schema=public --format=custom --no-owner --no-privileges --file="$FILE"
sha256sum "$FILE" > "$FILE.sha256"
echo "wrote $FILE ($(du -h "$FILE" | cut -f1)); checksum in $FILE.sha256"
