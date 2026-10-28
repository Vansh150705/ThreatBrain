"""Worker/queue semantics through the application layer (fake DB emulates claim_jobs).

The SQL itself (SKIP LOCKED, leases, dead-lettering) is verified on real PostgreSQL in
database/tests/test_queue.sh; these tests cover the Python layer on top of it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services import queue_service
from app.services.worker import PermanentJobError, Worker, register
from tests.conftest import ORG_A, ORG_B
from tests.test_pipeline import BRUTE


def _worker():
    return Worker(role="test", concurrency=2)


def test_failed_job_is_retried_with_backoff_then_dead_lettered(db, monkeypatch):
    calls = []

    @register("test.flaky")
    def _flaky(job):
        calls.append(job["attempts"])
        raise RuntimeError("boom")

    job = queue_service.enqueue(ORG_A, "test.flaky", {}, max_attempts=2)
    w = _worker()
    assert w.run_once(wait=True) == 1
    row = db.rows("jobs")[0]
    assert row["status"] == "queued" and row["attempts"] == 1 and "boom" in row["last_error"]
    assert datetime.fromisoformat(str(row["run_after"])) > datetime.now(UTC)  # backoff, not immediate
    # make it due again and let it fail its last attempt
    db.rows("jobs")[0]["run_after"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert w.run_once(wait=True) == 1
    row = db.rows("jobs")[0]
    assert row["status"] == "dead" and calls == [1, 2] and row["finished_at"]
    assert w.run_once(wait=True) == 0  # dead-lettered jobs are never claimed again
    w._pool.shutdown()
    assert job["id"] == row["id"]


def test_permanent_error_goes_straight_to_dead_letter(db):
    @register("test.bad")
    def _bad(job):
        raise PermanentJobError("payload can never work")

    queue_service.enqueue(ORG_A, "test.bad", {}, max_attempts=5)
    w = _worker()
    w.run_once(wait=True)
    row = db.rows("jobs")[0]
    assert row["status"] == "dead" and row["attempts"] == 1 and "never work" in row["last_error"]
    w._pool.shutdown()


def test_unknown_job_kind_is_dead_lettered_not_retried_forever(db):
    queue_service.enqueue(ORG_A, "no.such.kind", {})
    w = _worker()
    w.run_once(wait=True)
    assert db.rows("jobs")[0]["status"] == "dead"
    w._pool.shutdown()


def test_operator_can_requeue_a_dead_job_only_within_their_tenant(db):
    @register("test.once_bad")
    def _bad(job):
        raise PermanentJobError("x")

    job = queue_service.enqueue(ORG_A, "test.once_bad", {})
    w = _worker()
    w.run_once(wait=True)
    w._pool.shutdown()
    assert queue_service.requeue_dead(ORG_B, job["id"]) is None
    back = queue_service.requeue_dead(ORG_A, job["id"])
    assert back and back["status"] == "queued" and back["attempts"] == 0


def test_expired_lease_is_reclaimed_after_a_worker_dies(db):
    @register("test.ok")
    def _ok(job):
        return {"done": True}

    queue_service.enqueue(ORG_A, "test.ok", {})
    # a worker claims it and "dies": lease expires without completion
    claimed = queue_service.claim("dead-worker", 1)
    assert len(claimed) == 1 and db.rows("jobs")[0]["status"] == "running"
    db.rows("jobs")[0]["locked_until"] = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
    w = _worker()
    assert w.run_once(wait=True) == 1
    row = db.rows("jobs")[0]
    assert row["status"] == "succeeded" and row["attempts"] == 2
    w._pool.shutdown()


def test_job_is_not_given_to_two_workers(db):
    queue_service.enqueue(ORG_A, "test.ok", {})
    a = queue_service.claim("w1", 5)
    b = queue_service.claim("w2", 5)
    assert len(a) == 1 and b == []


def test_ingest_backpressure_returns_503_with_retry_after(client, auth, db, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "QUEUE_MAX_DEPTH_PER_ORG", 1)
    queue_service.reset_depth_cache()
    first = client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"), params={"async": "true"})
    assert first.status_code == 202
    queue_service.reset_depth_cache()
    second_body = {"event": {**BRUTE["event"], "source_ip": "203.0.113.43", "title": "another"}}
    r = client.post("/api/v1/ingest/event", json=second_body, headers=auth("analyst_a"), params={"async": "true"})
    assert r.status_code == 503 and r.headers["retry-after"] and r.json()["detail"]["error"] == "queue_full"
    assert len(db.rows("events")) == 1  # nothing was half-accepted


def test_batch_ingest_dedups_inside_and_across_batches(client, auth, db, drain):
    ev = {"title": "Port scan detected from 198.51.100.4", "event_type": "recon.port_scan",
          "source_ip": "198.51.100.4", "occurred_at": "2026-01-01T10:00:00Z"}
    body = {"events": [ev, ev, {**ev, "occurred_at": "2026-01-01T10:05:00Z"}], "source_system": "t"}
    r = client.post("/api/v1/ingest/events", json=body, headers=auth("analyst_a"))
    assert r.status_code == 202 and r.json()["accepted"] == 2 and r.json()["duplicates"] == 1
    again = client.post("/api/v1/ingest/events", json=body, headers=auth("analyst_a")).json()
    assert again["accepted"] == 0 and again["duplicates"] == 3
    assert drain() == 2


def test_tenant_isolation_in_event_store(client, auth, db, drain):
    client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_a"), params={"async": "true"})
    client.post("/api/v1/ingest/event", json=BRUTE, headers=auth("analyst_b"), params={"async": "true"})
    # the identical event in two tenants is two events, not a duplicate
    assert {e["organization_id"] for e in db.rows("events")} == {ORG_A, ORG_B}
    drain()
    assert {t["organization_id"] for t in db.rows("threats")} == {ORG_A, ORG_B}
    for t in db.rows("threat_events"):
        ev = next(e for e in db.rows("events") if e["id"] == t["event_id"])
        assert ev["organization_id"] == t["organization_id"]


def test_processing_a_deleted_event_is_a_noop(db):
    from app.services import event_processor

    assert event_processor.process_event(ORG_A, "00000000-0000-0000-0000-000000000000") == {"status": "missing"}


def test_non_matching_events_cost_no_llm_calls(client, auth, db, drain, llm):
    benign = {"event": {"title": "User logged in", "event_type": "authentication.success", "username": "alice"}}
    client.post("/api/v1/ingest/event", json=benign, headers=auth("analyst_a"), params={"async": "true"})
    drain()
    ev = db.rows("events")[0]
    assert ev["processed"] and not ev["alerted"] and not db.rows("threats")
    assert llm.calls == []


@pytest.mark.parametrize("mode,expect_runs", [("none", 0), ("all", 1)])
def test_triage_mode_controls_llm_spend(client, auth, db, drain, monkeypatch, mode, expect_runs):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "INGEST_TRIAGE_MODE", mode)
    benign = {"event": {"title": "User logged in", "event_type": "authentication.success", "username": "alice"}}
    client.post("/api/v1/ingest/event", json=benign, headers=auth("analyst_a"), params={"async": "true"})
    drain()
    assert len(db.rows("pipeline_runs")) == expect_runs


def test_correlation_fires_across_events_and_links_evidence(client, auth, db, drain):
    """Spray then successful login from one IP: each alone is a rule hit; together a critical correlation."""
    base = {"source": "authentication", "source_ip": "203.0.113.9", "asset_name": "vpn-01"}
    spray = {"event": {**base, "title": "Password spraying from 203.0.113.9", "event_type": "authentication.password_spraying",
                       "occurred_at": "2026-01-01T10:00:00Z"}}
    success = {"event": {**base, "title": "Login success after failures from 203.0.113.9",
                         "event_type": "authentication.brute_force_success", "occurred_at": "2026-01-01T10:20:00Z"}}
    client.post("/api/v1/ingest/event", json=spray, headers=auth("analyst_a"), params={"async": "true"})
    drain()
    client.post("/api/v1/ingest/event", json=success, headers=auth("analyst_a"), params={"async": "true"})
    drain()
    evs = sorted(db.rows("events"), key=lambda e: e["observed_at"])
    ids = [d["rule_id"] for d in evs[1]["detections"]]
    assert "TB-COR-001" in ids and "TB-AUTH-002" in ids
    assert "TB-COR-001" not in [d["rule_id"] for d in evs[0]["detections"]]
    # the supporting spray event is attached to the threat as evidence
    roles = {(te["event_id"], te["role"]) for te in db.rows("threat_events")}
    assert (evs[0]["id"], "supporting") in roles and (evs[1]["id"], "trigger") in roles
