"""Performance benchmark. Run: python -m bench.perf [--out bench/reports].

What each number means (read before quoting any of them):
  detection      the rule engine alone, one thread, on the validation corpus. Real CPU cost of detection.
  api_ingest     FastAPI app in-process (TestClient, no network) writing to an IN-MEMORY database stand-in. Measures
                 application overhead only; a real database adds network and SQL time per batch.
  worker         the worker pipeline (detect -> persist -> correlate) against the in-memory database, by concurrency.
                 Python threads share the GIL, so this does not predict multi-process scaling.
  postgres_queue claim_jobs() on a REAL PostgreSQL server with concurrent claimers (only when PGHOST etc. are set).
Not measured: LLM latency/throughput, network, a hosted Supabase, multi-node scaling.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))] if s else 0.0


def corpus():
    from validation import runner

    events = []
    for f in ("attacks.yaml", "benign.yaml"):
        for sc in runner.load(f):
            for e in sc["events"]:
                for x in runner.expand(e):
                    events.append(runner._event_dict(x))
    return events


def bench_detection(events, seconds=3.0):
    from app.detection.engine import get_engine

    eng = get_engine()
    lat, n = [], 0
    t_end = time.perf_counter() + seconds
    while time.perf_counter() < t_end:
        for ev in events:
            t0 = time.perf_counter()
            eng.evaluate(ev)
            lat.append((time.perf_counter() - t0) * 1000)
            n += 1
    total = sum(lat) / 1000
    return {"events": n, "rules": len(eng.rules), "events_per_second": round(n / total, 1),
            "latency_ms": {"p50": round(pct(lat, 50), 3), "p95": round(pct(lat, 95), 3), "p99": round(pct(lat, 99), 3), "max": round(max(lat), 3)}}


def _app():
    from fastapi.testclient import TestClient

    import tests.conftest as c
    from app.main import app
    from app.services import llm_service, queue_service, supabase_client
    from tests.fake_llm import FakeGroq
    from tests.fake_supabase import FakeSupabase

    fake = FakeSupabase()
    supabase_client.get_supabase_admin.cache_clear()
    supabase_client.create_client = lambda *a, **k: fake
    users = c.seed(fake)
    llm_service._get_groq_client = lambda: FakeGroq()
    queue_service.reset_depth_cache()
    from app.core.config import get_settings

    get_settings().QUEUE_MAX_DEPTH = 10**9
    get_settings().QUEUE_MAX_DEPTH_PER_ORG = 10**9
    return fake, TestClient(app), {"Authorization": f"Bearer {c.make_token(users['analyst_a'])}"}


def bench_api_ingest(events, batches=40, batch=50):
    fake, client, h = _app()
    lat, accepted = [], 0
    stamp = int(time.time())
    for b in range(batches):
        body = {"events": [{**e, "occurred_at": f"2026-01-01T00:{(b * batch + i) // 60 % 60:02d}:{(b * batch + i) % 60:02d}Z",
                            "raw_data": {**(e.get("raw_data") or {}), "bench": f"{stamp}-{b}-{i}"}}
                           for i, e in enumerate((events * 4)[:batch])], "source_system": "bench"}
        t0 = time.perf_counter()
        r = client.post("/api/v1/ingest/events", json=body, headers=h)
        lat.append((time.perf_counter() - t0) * 1000)
        accepted += r.json().get("accepted", 0)
    total = sum(lat) / 1000
    return {"batches": batches, "batch_size": batch, "accepted": accepted, "events_per_second": round(accepted / total, 1),
            "batch_latency_ms": {"p50": round(pct(lat, 50), 1), "p95": round(pct(lat, 95), 1), "max": round(max(lat), 1)}}


def bench_worker(events, n=300):
    from app.services import queue_service
    from app.services.worker import Worker

    out = {}
    for conc in (1, 2, 4, 8):
        fake, client, h = _app()
        from app.core.config import get_settings
        get_settings().INGEST_TRIAGE_MODE = "none"        # isolate detect+persist+correlate from the (scripted) LLM
        evs = [{**e, "occurred_at": "2026-01-01T10:00:00Z", "raw_data": {**(e.get("raw_data") or {}), "i": i}} for i, e in enumerate((events * 4)[:n])]
        for i in range(0, len(evs), 50):
            client.post("/api/v1/ingest/events", json={"events": evs[i:i + 50], "source_system": "bench"}, headers=h)
        queue_service.reset_depth_cache()
        w = Worker(role="bench", concurrency=conc)
        t0 = time.perf_counter()
        done = 0
        while True:
            k = w.run_once(wait=True)
            done += k
            if not k:
                break
        dt = time.perf_counter() - t0
        w._pool.shutdown(wait=True)
        out[f"concurrency_{conc}"] = {"jobs": done, "seconds": round(dt, 2), "events_per_second": round(done / dt, 1)}
    return out


def bench_postgres_queue(jobs=4000, claimers=8):
    if not os.environ.get("PGHOST"):
        return {"skipped": "set PGHOST/PGPORT/PGUSER and BENCH_PGDB (a migrated database) to run"}
    db = os.environ.get("BENCH_PGDB", "tb_migration_check")
    psql = ["psql", "-v", "ON_ERROR_STOP=1", "-At", "-q", db]
    subprocess.run([*psql, "-c", "truncate public.jobs"], check=True)
    subprocess.run([*psql, "-c", f"insert into public.jobs(kind, payload) select 'k', jsonb_build_object('n', g) from generate_series(1,{jobs}) g"], check=True)
    script = ("while :; do n=$(psql -At -q " + db + " -c \"with c as (select * from public.claim_jobs('w$1', 20, 60)) select count(*) from c\"); "
              "[ \"$n\" = 0 ] && break; done")
    t0 = time.perf_counter()
    procs = [subprocess.Popen(["bash", "-c", script, "_", str(i)]) for i in range(claimers)]
    [p.wait() for p in procs]
    dt = time.perf_counter() - t0
    claimed = int(subprocess.check_output([*psql, "-c", "select count(*) from public.jobs where status='running'"]).strip())
    dups = int(subprocess.check_output([*psql, "-c", "select count(*) from public.jobs where attempts<>1"]).strip())
    subprocess.run([*psql, "-c", "truncate public.jobs"], check=True)
    return {"jobs": jobs, "claimers": claimers, "claimed": claimed, "double_claimed": dups, "seconds": round(dt, 2),
            "claims_per_second": round(claimed / dt, 1), "note": "each claimer is a separate psql process (connection setup included)"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "reports"))
    args = ap.parse_args()
    events = corpus()
    report = {
        "schema": "threatbrain.perf/1", "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": {"python": platform.python_version(), "platform": platform.platform(), "cpus": os.cpu_count(),
                        "corpus_events": len(events), "caveats": __doc__.strip().splitlines()[2:]},
        "detection": bench_detection(events), "api_ingest": bench_api_ingest(events), "worker": bench_worker(events),
        "postgres_queue": bench_postgres_queue(),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "perf_report.json").write_text(json.dumps(report, indent=2))
    d, a, w, q = report["detection"], report["api_ingest"], report["worker"], report["postgres_queue"]
    print(f"detection      {d['events_per_second']:>9} events/s  p95 {d['latency_ms']['p95']} ms  ({d['rules']} rules)")
    print(f"api ingest     {a['events_per_second']:>9} events/s  batch p95 {a['batch_latency_ms']['p95']} ms (in-memory DB)")
    for k, v in w.items():
        print(f"worker {k:<14}{v['events_per_second']:>6} events/s")
    print(f"postgres queue {q}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
