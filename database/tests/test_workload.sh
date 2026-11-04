#!/usr/bin/env bash
# Real-PostgreSQL workload and failure-recovery tests (not a capacity claim: one small local server, psql clients).
#   PGHOST=... PGPORT=... PGUSER=... ./database/tests/test_workload.sh [db]       (db must already be migrated)
#
# What it proves:  exactly-once claiming under 12 concurrent workers; a worker killed with SIGKILL loses no job (lease expiry /
# transaction rollback); the correlation ledger reports exactly once under 16 racing writers; the behaviour-profile
# compare-and-swap loses no update under 12 racing writers.
# What it does NOT prove: production throughput/latency, replication, failover, or PgBouncer/Supabase pooler behaviour.
set -uo pipefail
DB="${1:-tb_migration_check}"
Q=(psql -v ON_ERROR_STOP=1 -At -q "$DB")
pass=0; failn=0
ok()   { echo "ok   $*"; pass=$((pass+1)); }
bad()  { echo "FAIL $*"; failn=$((failn+1)); }
check() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (expected '$2', got '$1')"; fi; }

org=$("${Q[@]}" -c "select id from public.organizations limit 1")
[ -n "$org" ] || { echo "FAIL no organization in $DB (run verify_migrations.sh first)"; exit 1; }
cleanup() { "${Q[@]}" -c "truncate public.jobs; delete from public.correlation_hits where dedupe_key like 'wl:%'; delete from public.behavior_profiles where entity_id like 'wl-%'" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup

# 1. throughput + exactly-once with concurrent workers claiming in batches and completing them
N=3000; W=12
"${Q[@]}" -c "insert into public.jobs(kind, payload) select 'wl', jsonb_build_object('n', g) from generate_series(1,$N) g"
t0=$(date +%s.%N)
for w in $(seq 1 $W); do
  (
    while :; do
      # claim a batch and complete it in one session (claim_jobs updates the rows itself, so completion is a separate statement)
      n=$(psql -v ON_ERROR_STOP=1 -At -q "$DB" <<SQL | tail -1
create temp table c as select id from public.claim_jobs('wl$w', 20, 60);
with u as (update public.jobs j set status='succeeded', finished_at=now() from c where j.id=c.id returning 1) select count(*) from u;
SQL
)
      [ "$n" = "0" ] && break
      case "$n" in ''|*[!0-9]*) echo "worker wl$w error" >&2; break;; esac
    done
  ) &
done
wait
t1=$(date +%s.%N)
check "$("${Q[@]}" -c "select count(*) from public.jobs where status='succeeded' and attempts=1")" "$N" "$N jobs each claimed and completed exactly once by $W concurrent workers"
rate=$(python3 -c "print(round($N/($t1-$t0)))")
echo "     (throughput on this scratch server: ~$rate jobs/s with psql-process clients; indicative only)"

# 2a. a worker that dies (SIGKILL) while holding an OPEN claim transaction: the claim rolls back, nothing is stuck
"${Q[@]}" -c "truncate public.jobs; insert into public.jobs(kind) select 'wl' from generate_series(1,60)"
# (idle-in-transaction, as a real worker is between claiming and processing; the server notices the dead socket at once)
( echo "begin; select count(*) from public.claim_jobs('doomed', 60, 60);"; sleep 60 ) | psql -q -At -v marker=doomed-worker "$DB" >/dev/null 2>&1 &
pid=$!
sleep 1.5
pkill -9 -f 'marker=doomed-worker'; pkill -P $pid sleep 2>/dev/null; wait $pid 2>/dev/null     # psql is a perl wrapper around the real client: kill both
sleep 1.5
got=$("${Q[@]}" -c "select count(*) from public.claim_jobs('survivor', 100, 60)")
check "$got" "60" "all 60 jobs claimable by a survivor after the claiming connection was SIGKILLed mid-transaction"
check "$("${Q[@]}" -c "select count(*) from public.jobs where attempts <> 1")" "0" "no attempt was burned by the aborted claim"

# 2b. a worker that dies AFTER its claim committed: the lease expires and another worker takes the jobs over
"${Q[@]}" -c "truncate public.jobs; insert into public.jobs(kind, max_attempts) select 'wl', 3 from generate_series(1,40)"
( "${Q[@]}" -c "select count(*) from public.claim_jobs('crashed', 40, 2)" >/dev/null; sleep 60 ) &
pid=$!
sleep 1; kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null
check "$("${Q[@]}" -c "select count(*) from public.claim_jobs('early', 40, 60)")" "0" "jobs held under a live lease are not stolen"
sleep 2.5
taken=$("${Q[@]}" -c "select count(*) from public.claim_jobs('takeover', 100, 60)")
check "$taken" "40" "all 40 jobs reclaimed by another worker once the dead worker's lease expired"
check "$("${Q[@]}" -c "select count(*) from public.jobs where attempts=2 and locked_by='takeover'")" "40" "the takeover counts as attempt 2 (poison jobs still reach the dead-letter state)"

# 3. correlation ledger: 16 writers race to report the same completion, exactly one wins
for w in $(seq 1 16); do
  ( "${Q[@]}" -c "insert into public.correlation_hits(organization_id, dedupe_key, correlation_id) values ('$org', 'wl:race', 'TB-COR-X') on conflict do nothing returning 1" ) > /tmp/tb_wl_ledger_$w.out &
done
wait
winners=$(cat /tmp/tb_wl_ledger_*.out | grep -c '^1$'); rm -f /tmp/tb_wl_ledger_*.out
check "$winners" "1" "16 racing workers: exactly one reports the correlation (exactly-once ledger)"

# 4. behaviour-profile compare-and-swap: no lost update under contention
"${Q[@]}" -c "insert into public.behavior_profiles(organization_id, entity_type, entity_id, state) values ('$org','user','wl-cas','{}')"
INC=15
for w in $(seq 1 12); do
  (
    done_n=0
    while [ $done_n -lt $INC ]; do
      v=$("${Q[@]}" -c "select version from public.behavior_profiles where organization_id='$org' and entity_type='user' and entity_id='wl-cas'")
      r=$("${Q[@]}" -c "update public.behavior_profiles set version=version+1, event_count=event_count+1 where organization_id='$org' and entity_type='user' and entity_id='wl-cas' and version=$v returning 1")
      [ "$r" = "1" ] && done_n=$((done_n+1))
    done
  ) &
done
wait
check "$("${Q[@]}" -c "select event_count from public.behavior_profiles where entity_id='wl-cas'")" "$((12*INC))" "12 writers x $INC compare-and-swap increments: no lost update"
check "$("${Q[@]}" -c "select version from public.behavior_profiles where entity_id='wl-cas'")" "$((12*INC+1))" "version advanced exactly once per accepted write"

echo "---- $pass passed, $failn failed"
[ "$failn" = "0" ]
