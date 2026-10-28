#!/usr/bin/env bash
# Ordered, checksummed, locked schema migrations for PostgreSQL / Supabase.
#
#   DATABASE_URL=postgresql://... ./migrate.sh            apply every pending migration
#   DATABASE_URL=...              ./migrate.sh --status   show applied / pending / drifted files
#   DATABASE_URL=...              ./migrate.sh --dry-run  list what would be applied, change nothing
#   DATABASE_URL=...              ./migrate.sh --baseline 023   record 001..023 as already applied
#                                                         (for databases set up by hand in the SQL editor)
#
# Guarantees
#   * each file runs in its own psql session and its own transaction (the enum-adding files 022/024 need that)
#   * a file that was applied and has since been edited is REFUSED (checksum drift) rather than re-run
#   * a Postgres advisory lock stops two deploys from migrating at once
#   * files apply in filename order; the first failure stops the run and leaves earlier files recorded
#   * migrations are idempotent (IF NOT EXISTS / OR REPLACE), so re-running after a partial failure is safe
#
# Env: DATABASE_URL (required), MIGRATE_NO_VECTOR=1 (test databases without pgvector only).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${DATABASE_URL:?set DATABASE_URL (e.g. postgresql://postgres:...@db.xxx.supabase.co:5432/postgres)}"
MODE=apply; BASELINE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --status) MODE=status ;;
    --dry-run) MODE=dry ;;
    --baseline) MODE=baseline; BASELINE="${2:?--baseline needs a migration number, e.g. 023}"; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac; shift
done
P=(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -X)
sha() { sha256sum "$1" | cut -d' ' -f1; }

"${P[@]}" -c "create table if not exists public.schema_migrations (filename text primary key, checksum text, applied_at timestamptz not null default now())"

recorded() { "${P[@]}" -At -c "select checksum from public.schema_migrations where filename='$1'"; }


# Hold one advisory lock, on a dedicated connection, for the whole run so two deploys cannot interleave.
if [ "$MODE" = "apply" ] || [ "$MODE" = "baseline" ]; then
  coproc LOCKER { psql "$DATABASE_URL" -X -At -q; }
  trap 'echo "\\q" >&"${LOCKER[1]}" 2>/dev/null || true' EXIT
  echo "select pg_advisory_lock(727274);" >&"${LOCKER[1]}"
  read -r _ <&"${LOCKER[0]}"   # blocks until the lock is ours
fi

pending=0; drift=0; applied=0
shopt -s nullglob
for f in "$HERE"/migrations/0*.sql; do
  name="$(basename "$f")"; sum="$(sha "$f")"; num="${name%%_*}"
  have="$(recorded "$name")"
  if [ -n "$have" ] && [ "$have" = "$sum" ]; then
    [ "$MODE" = "status" ] && echo "applied   $name"
    continue
  fi
  if [ -n "$have" ] && [ "$have" != "$sum" ]; then
    echo "DRIFT     $name was applied with a different checksum (the file was edited after it was applied)"; drift=1
    [ "$MODE" = "apply" ] && { echo "refusing to continue; restore the original file or add a new migration" >&2; exit 3; }
    continue
  fi
  pending=1
  case "$MODE" in
    status|dry) echo "pending   $name" ;;
    baseline)
      if [ "$((10#$num))" -le "$((10#$BASELINE))" ]; then
        "${P[@]}" -c "insert into public.schema_migrations(filename, checksum) values ('$name','$sum') on conflict (filename) do nothing"
        echo "baseline  $name"
      fi ;;
    apply)
      src="$(cat "$f")"
      if [ "${MIGRATE_NO_VECTOR:-0}" = "1" ]; then
        src="$(python3 - "$f" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
s = re.sub(r'extensions\.vector\(\d+\)', 'float4[]', s)
s = re.sub(r'CREATE EXTENSION[^;]*vector[^;]*;', '', s, flags=re.I)
s = re.sub(r'CREATE INDEX IF NOT EXISTS \w+\s+ON public\.agent_memory[^;]*USING hnsw[^;]*;', '', s, flags=re.I | re.S)
print(s)
PY
)"
      fi
      echo "applying  $name"
      # One session per file: run the file in a single transaction together with its bookkeeping row.
      { echo "begin;"; echo "$src"; echo "insert into public.schema_migrations(filename, checksum) values ('$name','$sum') on conflict (filename) do update set checksum=excluded.checksum, applied_at=now();"; echo "commit;"; } \
        | "${P[@]}" >/dev/null
      applied=$((applied+1)) ;;
  esac
done

case "$MODE" in
  status) [ "$drift" = 1 ] && exit 3 || { [ "$pending" = 0 ] && echo "up to date"; exit 0; } ;;
  dry)    [ "$pending" = 0 ] && echo "nothing to apply" ;;
  apply)  echo "done: $applied migration(s) applied" ;;
esac
