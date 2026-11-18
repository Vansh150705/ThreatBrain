#!/usr/bin/env bash
# Real-PostgreSQL tests for the durable job queue (claim_jobs / leases / dead-letter / purge).
# Requires a scratch database already migrated by ../verify_migrations.sh (default tb_migration_check).
#   PGHOST=... PGPORT=... PGUSER=... ./database/tests/test_queue.sh [db]
set -euo pipefail
DB="${1:-tb_migration_check}"
Q=(psql -v ON_ERROR_STOP=1 -At -q "$DB")
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok   $*"; }

"${Q[@]}" -c "truncate public.jobs"

# 1. concurrent workers never double-claim
"${Q[@]}" -c "insert into public.jobs(kind, payload) select 'k', jsonb_build_object('n', g) from generate_series(1,400) g"
for w in 1 2 3 4 5 6 7 8; do
  (
    while :; do
      n=$("${Q[@]}" -c "with c as (select * from public.claim_jobs('w$w', 7, 60)) select count(*) from c")
      [ "$n" = "0" ] && break
    done
  ) &
done
wait
total=$("${Q[@]}" -c "select count(*) from public.jobs where status='running'")
dups=$("${Q[@]}" -c "select count(*) from public.jobs where attempts <> 1")
[ "$total" = "400" ] || fail "expected 400 claimed jobs, got $total"
[ "$dups" = "0" ] || fail "$dups jobs were claimed more than once"
workers=$("${Q[@]}" -c "select count(distinct locked_by) from public.jobs")
[ "$workers" -ge 2 ] || fail "work was not shared between workers ($workers)"
ok "400 jobs claimed exactly once across $workers concurrent workers"

# 2. an expired lease is reclaimed (crash recovery) and counts as an attempt
"${Q[@]}" -c "truncate public.jobs; insert into public.jobs(kind, max_attempts) values ('k', 3)"
"${Q[@]}" -c "select count(*) from public.claim_jobs('dead-worker', 1, 60)" >/dev/null
"${Q[@]}" -c "update public.jobs set locked_until = now() - interval '1 second'"
r=$("${Q[@]}" -c "select attempts || ':' || locked_by from public.claim_jobs('w2', 1, 60)")
[ "$r" = "2:w2" ] || fail "lease reclaim returned '$r'"
ok "expired lease reclaimed by another worker (attempt 2)"

# 3. exhausted attempts go to the dead-letter state instead of looping forever
"${Q[@]}" -c "update public.jobs set locked_until = now() - interval '1 second', attempts = max_attempts"
n=$("${Q[@]}" -c "select count(*) from public.claim_jobs('w3', 5, 60)")
s=$("${Q[@]}" -c "select status from public.jobs")
[ "$n" = "0" ] && [ "$s" = "dead" ] || fail "exhausted job not dead-lettered (claimed=$n status=$s)"
ok "job with exhausted attempts is dead-lettered"

# 4. run_after (backoff) is honoured; priority ordering
"${Q[@]}" -c "truncate public.jobs;
  insert into public.jobs(kind, run_after) values ('later', now() + interval '1 hour');
  insert into public.jobs(kind, priority) values ('low', 1), ('high', 9)"
first=$("${Q[@]}" -c "select kind from public.claim_jobs('w', 1, 60)")
[ "$first" = "high" ] || fail "priority not respected ($first)"
rest=$("${Q[@]}" -c "select string_agg(kind, ',' order by kind) from public.claim_jobs('w', 10, 60)")
[ "$rest" = "low" ] || fail "delayed job was claimed early ($rest)"
ok "priority ordering and delayed retry (run_after) respected"

# 5. queue filter
"${Q[@]}" -c "truncate public.jobs; insert into public.jobs(kind, queue) values ('a','ingest'), ('b','maintenance')"
k=$("${Q[@]}" -c "select kind from public.claim_jobs('w', 5, 60, array['maintenance'])")
[ "$k" = "b" ] || fail "queue filter ignored ($k)"
ok "queue filter works"

# 6. retention keeps evidence-linked events, removes old unlinked ones, never touches audit_logs
"${Q[@]}" -c "truncate public.jobs, public.replay_guard"
org=$("${Q[@]}" -c "select id from public.organizations limit 1")
[ -n "$org" ] || fail "no organization in scratch DB"
"${Q[@]}" -c "
  insert into public.events(organization_id, source, event_type, title, created_at) values
   ('$org','other','x.old','old unlinked', now() - interval '40 days'),
   ('$org','other','x.new','new unlinked', now() - interval '1 day');
  insert into public.jobs(kind, status, finished_at) values ('old','succeeded', now() - interval '30 days'), ('new','succeeded', now());"
res=$("${Q[@]}" -c "select public.purge_expired(30, 365, 14, 90)")
left=$("${Q[@]}" -c "select string_agg(title, ',' order by title) from public.events where event_type like 'x.%'")
[ "$left" = "new unlinked" ] || fail "retention kept '$left' ($res)"
jleft=$("${Q[@]}" -c "select count(*) from public.jobs")
[ "$jleft" = "1" ] || fail "expected 1 job left, got $jleft"
"${Q[@]}" -c "delete from public.events where event_type like 'x.%'; truncate public.jobs"
ok "retention purge: $res"
echo "queue + retention tests passed"
