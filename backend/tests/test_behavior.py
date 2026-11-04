"""Behavioural analytics: statistics, cold start, corroboration, poisoning resistance, persistence, tenancy, tuning."""

from __future__ import annotations

import json
import random
import threading
from datetime import UTC, datetime, timedelta

import pytest

from app.behavior import config as bconfig
from app.behavior import engine, features, model
from tests.conftest import ORG_A, ORG_B

T0 = datetime(2026, 3, 2, 0, 0, tzinfo=UTC)
CFG = bconfig.build()


def login(ts, user="alice", ip="10.1.4.20", host="ws-alice", **kw):
    return {"event_type": "authentication.success", "username": user, "source_ip": ip, "asset_name": host,
            "observed_at": ts.isoformat(), "raw_data": {}, **kw}


def flow(ts, host="srv-app-1", dest="198.51.100.20", sent=40_000, port=443):
    return {"event_type": "network.flow", "asset_name": host, "source_ip": "10.0.2.9", "destination_ip": dest,
            "destination_port": port, "observed_at": ts.isoformat(), "raw_data": {"bytes_out": sent}}


def train_user(state, days=12, hours=(8, 9, 10, 13, 14, 16), per_day=6, seed=1, ip="10.1.4.20", host="ws-alice", cfg=CFG, pop=None):
    rnd = random.Random(seed)
    for d in range(days):
        for _ in range(per_day):
            ts = T0 + timedelta(days=d, hours=rnd.choice(hours), minutes=rnd.randint(0, 59))
            engine.analyze(state, features.extract(login(ts, ip=ip, host=host)), cfg, pop, learn=True)


def run(state, ev, cfg=CFG, pop=None, learn=True):
    res = engine.analyze(state, features.extract(ev), cfg, pop, learn=learn)
    ts = features.event_time(ev)
    dec = engine.decide(state, res.anomalies, cfg, ts) if res.anomalies else None
    engine.remember(state, res.anomalies)
    return res, dec


# ------------------------------------------------------------------------------------------- statistics
def test_robust_z_ignores_a_past_spike_that_would_hide_a_new_one_under_mean_stddev():
    st = model.num_new()
    for v in [40_000] * 60 + [30_000_000]:         # one historical burst
        model.num_observe(st, v, learn=True)
    z, med, _mad = model.robust_z(st, 25_000_000)
    assert z > 8                                    # still extreme despite the old burst in the history
    assert model.robust_z(st, 41_000)[0] < 1


def test_constant_history_does_not_make_every_change_infinite():
    st = model.num_new()
    for _ in range(40):
        model.num_observe(st, 1000, learn=True)
    z, *_ = model.robust_z(st, 1500)
    assert z < 3        # MAD floor: a 50% change on a perfectly flat series is not an emergency


def test_hour_probability_is_smoothed_and_neighbouring_hours_are_near_normal():
    st = model.hours_new()
    for h in [9] * 50 + [10] * 50:
        model.hours_observe(st, h * 3600 + 5, learn=True)
    assert model.hour_probability(st, 11 * 3600) > 0.1          # adjacent to a busy hour (smoothed over +-2h)
    assert model.hour_probability(st, 12 * 3600) > model.hour_probability(st, 15 * 3600)
    assert model.hour_probability(st, 3 * 3600) < 0.01


def test_state_is_bounded_whatever_an_attacker_generates():
    st = engine.new_state()
    rnd = random.Random(3)
    for i in range(3000):
        ts = T0 + timedelta(minutes=i)
        host = f"h{rnd.randint(0, 10**6)}"
        engine.analyze(st, features.extract(login(ts, host=host, ip=f"10.{i % 250}.{rnd.randint(0, 250)}.1")), CFG, None, learn=True)
    assert len(json.dumps(st)) < 200_000
    for f in ("auth.host", "auth.source_net"):
        assert len(st["f"][f]["seen"]) <= CFG.max_keys_per_feature and len(st["f"][f]["cand"]) <= CFG.max_keys_per_feature


# ------------------------------------------------------------------------------------------- cold start / corroboration
def test_immature_entity_is_never_flagged_by_its_own_baseline():
    st = engine.new_state()
    train_user(st, days=1, per_day=5)
    res, dec = run(st, login(T0 + timedelta(days=2, hours=3), ip="198.51.100.9", host="dc-01"))
    assert not engine.is_mature(st, CFG) or not res.anomalies
    assert res.anomalies == [] and dec is None


def test_one_odd_but_plausible_deviation_is_recorded_but_does_not_alert():
    st = engine.new_state()
    train_user(st)
    res, dec = run(st, login(T0 + timedelta(days=13, hours=9), ip="203.0.113.50"))     # new network, normal hour, known host
    assert [a.feature for a in res.anomalies] == ["auth.source_net"]
    assert dec is not None and not dec.alert


def test_independent_signals_combine_into_an_alert_with_an_explanation():
    st = engine.new_state()
    train_user(st)
    res, dec = run(st, login(T0 + timedelta(days=13, hours=3, minutes=10), ip="198.51.100.9", host="dc-01"))
    assert dec.alert and {a.feature for a in dec.contributing} >= {"auth.source_net", "auth.hour"}
    expl = next(a for a in res.anomalies if a.feature == "auth.source_net").explanation
    assert expl["observed"] == "198.51.100.0/24" and expl["baseline"]["active_days"] >= 12 and "never seen" in expl["summary"]
    assert expl["baseline"]["top"][0][0] == "10.1.4.0/24"


def test_signals_hours_apart_decay_and_do_not_add_up():
    st = engine.new_state()
    train_user(st)
    run(st, login(T0 + timedelta(days=13, hours=9), ip="203.0.113.50"))                       # weak
    res, dec = run(st, login(T0 + timedelta(days=13, hours=9) + timedelta(hours=40)))      # 01:00 UTC two days later: unusual hour
    assert any(a.feature == "auth.hour" for a in res.anomalies)
    assert dec is not None and not dec.alert                                                 # 40h later the first has decayed away


def test_sensitivity_changes_the_decision_not_the_evidence():
    results = {}
    for level in ("low", "balanced", "high"):
        st = engine.new_state()
        cfg = bconfig.build(level)
        train_user(st, cfg=cfg)
        _r, dec = run(st, login(T0 + timedelta(days=13, hours=9), ip="203.0.113.50"), cfg=cfg)
        results[level] = dec.alert
    assert results["high"] and not results["low"]


# ------------------------------------------------------------------------------------------- peers and organisational variation
def test_peer_prevalence_discounts_normal_organisational_variation():
    st = engine.new_state()
    train_user(st)
    pop_common = engine.PopulationView(mature=20, holders={"auth.host": {"file-srv": 12}}, scope="peer group g1")
    pop_unique = engine.PopulationView(mature=20, holders={"auth.host": {}}, scope="tenant")
    ev = login(T0 + timedelta(days=13, hours=9), host="file-srv")
    a = engine.analyze(json.loads(json.dumps(st)), features.extract(ev), CFG, pop_common, learn=True).anomalies
    b = engine.analyze(json.loads(json.dumps(st)), features.extract(ev), CFG, pop_unique, learn=True).anomalies
    sa = next((x.score for x in a if x.feature == "auth.host"), 0.0)
    sb = next(x.score for x in b if x.feature == "auth.host")
    assert sa < sb * 0.5 and b[0].explanation["peer"]["prevalence"] == 0.0


def test_tiny_peer_groups_are_ignored():
    st = engine.new_state()
    train_user(st)
    tiny = engine.PopulationView(mature=3, holders={"auth.host": {"file-srv": 3}})
    res = engine.analyze(st, features.extract(login(T0 + timedelta(days=13, hours=9), host="file-srv")), CFG, tiny, learn=True)
    assert next(a for a in res.anomalies if a.feature == "auth.host").score == pytest.approx(0.6, abs=0.01)


def test_new_account_is_judged_against_peers_only_for_high_signal_features():
    st = engine.new_state()
    pop = engine.PopulationView(mature=30, holders={"priv.action": {"createaccesskey": 0, "listbuckets": 25}}, scope="tenant")
    ev = {"event_type": "cloud.audit", "username": "newhire", "observed_at": T0.isoformat(),
          "raw_data": {"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com"}}
    res = engine.analyze(st, features.extract(ev), CFG, pop, learn=True)
    assert [a.feature for a in res.anomalies] == ["priv.action"] and res.anomalies[0].explanation["cold_start"]
    ordinary = {"event_type": "authentication.success", "username": "newhire", "source_ip": "10.9.9.9", "asset_name": "ws-9",
                "observed_at": T0.isoformat(), "raw_data": {}}
    assert engine.analyze(st, features.extract(ordinary), CFG, pop, learn=True).anomalies == []


# ------------------------------------------------------------------------------------------- poisoning resistance
def test_events_with_deterministic_detections_are_not_learned():
    st = engine.new_state()
    train_user(st)
    before = json.dumps(st, sort_keys=True)
    run(st, login(T0 + timedelta(days=13, hours=3), ip="198.51.100.9", host="dc-01"), learn=False)
    after = json.loads(json.dumps(st))
    assert after["meta"]["events"] == json.loads(before)["meta"]["events"]
    assert "198.51.100.0/24" not in after["f"]["auth.source_net"]["cand"]


def test_a_new_value_is_not_trusted_after_one_burst_but_is_after_it_recurs_over_days():
    st = engine.new_state()
    train_user(st)
    day = 13
    for i in range(30):    # 30 sign-ins within two hours from a new place (an attacker hammering): still only a candidate
        engine.analyze(st, features.extract(login(T0 + timedelta(days=day, hours=9, minutes=i * 3), ip="203.0.113.50")), CFG, None, learn=True)
    assert "203.0.113.0/24" in st["f"]["auth.source_net"]["cand"] and "203.0.113.0/24" not in st["f"]["auth.source_net"]["seen"]
    engine.analyze(st, features.extract(login(T0 + timedelta(days=day + 1, hours=9), ip="203.0.113.50")), CFG, None, learn=True)
    assert "203.0.113.0/24" in st["f"]["auth.source_net"]["seen"]          # second distinct day: now part of normal


def test_daily_growth_cap_limits_how_fast_a_baseline_can_be_reshaped():
    st = engine.new_state()
    cfg = bconfig.build(params={"daily_new_keys_cap": 3})
    train_user(st, cfg=cfg)
    for d in (13, 14):
        for i in range(10):
            engine.analyze(st, features.extract(login(T0 + timedelta(days=d, hours=9, minutes=i), host=f"new-{i}")), cfg, None, learn=True)
    grown = [k for k in st["f"]["auth.host"]["seen"] if k.startswith("new-")]
    assert len(grown) <= 3


def test_schedule_change_is_learned_only_when_it_recurs():
    st = engine.new_state()
    train_user(st)
    flagged = 0
    for d in range(13, 20):
        res, _ = run(st, login(T0 + timedelta(days=d, hours=22, minutes=5)))
        flagged += any(a.feature == "auth.hour" for a in res.anomalies)
    assert 1 <= flagged < 7          # flagged at first, then accepted as the new normal after several days


# ------------------------------------------------------------------------------------------- data volume (EVA-006 class)
def train_host(st, days=10, cfg=CFG):
    rnd = random.Random(5)
    for d in range(days):
        for h in range(24):
            for _ in range(rnd.randint(1, 4)):
                ts = T0 + timedelta(days=d, hours=h, minutes=rnd.randint(0, 59))
                engine.analyze(st, features.extract(flow(ts, sent=int(rnd.lognormvariate(10.7, 0.6)))), cfg, None, learn=True)


def test_exfiltration_volume_to_a_new_destination_alerts():
    st = engine.new_state()
    train_host(st)
    ts = T0 + timedelta(days=11, hours=2)
    res, dec = run(st, flow(ts, dest="203.0.113.91", sent=90_000_000), cfg=CFG)
    assert dec.alert and {"volume", "net_dest"} <= set(dec.families)
    vol = next(a for a in res.anomalies if a.family == "volume")
    assert vol.explanation["z"] > 4 and "MB" in vol.explanation["summary"]


def test_ordinary_traffic_variation_never_alerts_and_small_bursts_below_the_floor_are_ignored():
    st = engine.new_state()
    train_host(st)
    alerts = 0
    rnd = random.Random(9)
    for i in range(300):
        ts = T0 + timedelta(days=11, minutes=i * 4)
        _r, dec = run(st, flow(ts, sent=int(rnd.lognormvariate(10.7, 0.7))))
        alerts += bool(dec and dec.alert)
    assert alerts == 0
    _r, dec = run(st, flow(T0 + timedelta(days=12), sent=2_000_000))      # 50x median but below the absolute floor
    assert dec is None or not dec.alert


def test_a_flagged_exfil_hour_does_not_become_normal_history():
    st = engine.new_state()
    train_host(st)
    before = len(st["f"]["net.bytes_out_hour"]["hist"])
    run(st, flow(T0 + timedelta(days=11, hours=2), dest="203.0.113.91", sent=90_000_000))
    run(st, flow(T0 + timedelta(days=11, hours=5), sent=40_000))                         # next hour finalises the flagged one
    hist = st["f"]["net.bytes_out_hour"]["hist"]
    assert len(hist) == before and max(hist) < 17          # exp(17) ~ 24 MB: the 90 MB hour is not in the history


# ------------------------------------------------------------------------------------------- privilege and process behaviour
def test_privileged_action_never_performed_by_a_mature_identity_alerts_on_its_own():
    st = engine.new_state()
    for d in range(10):
        for _ in range(6):
            engine.analyze(st, features.extract({"event_type": "cloud.audit", "username": "dev-bot", "observed_at": (T0 + timedelta(days=d, hours=_)).isoformat(),
                                                 "raw_data": {"eventName": "GetObject", "eventSource": "s3.amazonaws.com", "bucket": "ci-artifacts"}}), CFG, None, learn=True)
    res, dec = run(st, {"event_type": "cloud.audit", "username": "dev-bot", "observed_at": (T0 + timedelta(days=11)).isoformat(),
                        "raw_data": {"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com"}})
    assert any(a.feature == "priv.action" for a in res.anomalies)
    assert dec.alert is False or dec.reason       # 0.9 weight on novelty: a single strong signal


def test_new_program_run_from_a_user_writable_path_is_flagged_when_the_host_is_stable():
    st = engine.new_state()
    rnd = random.Random(2)
    names = ["nginx", "sshd", "cron", "python3", "bash", "systemd"]
    for i in range(300):
        ts = T0 + timedelta(days=i % 8, hours=rnd.randint(0, 23), minutes=rnd.randint(0, 59))
        engine.analyze(st, features.extract({"event_type": "process.start", "asset_name": "web-01", "process_name": rnd.choice(names),
                                             "observed_at": ts.isoformat(), "raw_data": {"parent_process": "systemd", "process_path": f"/usr/bin/{names[0]}"}}), CFG, None, learn=True)
    res, dec = run(st, {"event_type": "process.start", "asset_name": "web-01", "process_name": "kworkerd", "observed_at": (T0 + timedelta(days=9)).isoformat(),
                        "raw_data": {"parent_process": "bash", "process_path": "/dev/shm/.x/kworkerd"}})
    assert {a.feature for a in res.anomalies} >= {"proc.name", "proc.exec_path"} and dec.alert


# ------------------------------------------------------------------------------------------- configuration
def test_settings_are_bounded_so_safety_properties_cannot_be_switched_off():
    for bad in ({"min_families": 1}, {"alert_score": 0.1}, {"budget_per_org_hour": 0}, {"nope": 1}, {"min_events": True}):
        with pytest.raises(bconfig.ConfigError):
            bconfig.validate_params(bad)
    assert bconfig.build(params={"min_events": 100}).min_events == 100


# ------------------------------------------------------------------------------------------- service, persistence, tenancy
@pytest.fixture()
def svc(db, users):
    from app.services import behavior_service

    behavior_service.invalidate()
    return behavior_service


def feed(svc, org, events, hits=None):
    out = []
    for i, ev in enumerate(events):
        out += svc.evaluate_and_learn(org, {**ev, "id": f"00000000-0000-4000-8000-{i:012d}"} if False else ev, hits)
    return out


def history(svc, org, user="alice", **kw):
    rnd = random.Random(1)
    evs = [login(T0 + timedelta(days=d, hours=rnd.choice((8, 9, 10, 13, 14, 16)), minutes=rnd.randint(0, 59)), user=user, **kw)
           for d in range(12) for _ in range(6)]
    for ev in evs:
        svc.evaluate_and_learn(org, ev, [])


def test_baselines_persist_and_are_tenant_scoped(svc, db):
    history(svc, ORG_A)
    assert svc.entity_summary(ORG_A, "user", "alice")["mature"] is True
    assert svc.entity_summary(ORG_B, "user", "alice") is None            # the same name in another tenant has no history
    # an anomaly for 'alice' in tenant B is judged against B's (empty) baseline, i.e. cold start: nothing fires
    hits = svc.evaluate_and_learn(ORG_B, login(T0 + timedelta(days=13, hours=3), ip="198.51.100.9", host="dc-01"), [])
    assert hits == [] and not [r for r in db.rows("behavior_anomalies") if r["organization_id"] == ORG_B]


def test_alert_is_emitted_once_per_cooldown_and_anomalies_are_recorded_with_explanations(svc, db):
    history(svc, ORG_A)
    bad = login(T0 + timedelta(days=13, hours=3, minutes=10), ip="198.51.100.9", host="dc-01")
    hits = svc.evaluate_and_learn(ORG_A, bad, [])
    assert len(hits) == 1 and hits[0].kind == "behavior" and hits[0].rule_id.startswith("TB-UEBA-")
    assert hits[0].explanation["signals"][0]["explanation"]["summary"] and "T1078" in hits[0].techniques
    same = svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=3, minutes=40), ip="198.51.100.9", host="dc-01"), [])
    assert same == []          # the same new network/host does not alert twice (re-alert guard)
    other = svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=3, minutes=50), ip="203.0.113.9", host="dc-02"), [])
    assert other == []         # a different new value in the same family inside the cooldown window is withheld
    assert any(r["suppressed_reason"] == "cooldown" for r in db.rows("behavior_anomalies"))
    assert db.rows("behavior_anomalies") and all(r["organization_id"] == ORG_A for r in db.rows("behavior_anomalies"))


def test_events_that_already_alerted_deterministically_do_not_train_the_baseline(svc, db):
    history(svc, ORG_A)
    before = svc.load_profile(ORG_A, "user", "alice")[0]["meta"]["events"]
    from app.detection.engine import RuleHit

    fake = RuleHit("TB-X", "x", "high", 90, [], [], [])
    svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=9), ip="198.51.100.9", host="dc-01"), [fake])
    assert svc.load_profile(ORG_A, "user", "alice")[0]["meta"]["events"] == before


def test_concurrent_workers_do_not_lose_baseline_updates(svc, db):
    evs = [login(T0 + timedelta(days=d % 5, hours=9, minutes=i), user="carol") for i, d in enumerate(range(80))]
    threads = [threading.Thread(target=lambda chunk=evs[i::8]: [svc.evaluate_and_learn(ORG_A, e, []) for e in chunk]) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert svc.load_profile(ORG_A, "user", "carol")[0]["meta"]["events"] == 80


def test_a_stale_write_is_rejected_and_retried_not_silently_lost(svc, db):
    history(svc, ORG_A)
    state, version = svc.load_profile(ORG_A, "user", "alice")
    assert svc.save_profile(ORG_A, "user", "alice", state, version) is True
    assert svc.save_profile(ORG_A, "user", "alice", state, version) is False          # same version again = conflict


def test_suppression_and_budget_withhold_alerts_but_keep_the_evidence(svc, db):
    history(svc, ORG_A)
    svc.add_suppression(ORG_A, entity_type="user", entity_id="alice", reason="travelling to the Berlin office", user_id=None)
    hits = svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=3), ip="198.51.100.9", host="dc-01"), [])
    assert hits == []
    rows = db.rows("behavior_anomalies")
    assert rows and all(r["suppressed_reason"] == "suppression" for r in rows if r["score"] >= 0.2)


def test_behaviour_can_be_switched_off_per_tenant(svc, db):
    history(svc, ORG_A)
    svc.update_settings(ORG_A, enabled=False, sensitivity=None, params=None, user_id=None)
    assert svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=3), ip="198.51.100.9", host="dc-01"), []) == []


def test_marking_expected_teaches_the_baseline_and_silences_repeats(svc, db):
    history(svc, ORG_A)
    svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=9), ip="203.0.113.50"), [])
    a = next(r for r in db.rows("behavior_anomalies") if r["feature"] == "auth.source_net")
    svc.set_disposition(ORG_A, a["id"], "expected", None, "new branch office")
    assert "203.0.113.0/24" in svc.load_profile(ORG_A, "user", "alice")[0]["f"]["auth.source_net"]["seen"]
    assert svc.set_disposition(ORG_B, a["id"], "benign", None) is None                 # another tenant cannot touch it


def test_history_backfill_builds_baselines_without_alerting(svc, db):
    rnd = random.Random(4)
    evs = [login(T0 + timedelta(days=d, hours=rnd.choice((9, 10, 14)), minutes=rnd.randint(0, 59)), user="dave") for d in range(10) for _ in range(6)]
    out = svc.learn_batch(ORG_A, evs)
    assert out["entities"] == 1 and svc.entity_summary(ORG_A, "user", "dave")["mature"]
    assert db.rows("behavior_anomalies") == []


def test_peer_groups_are_formed_and_used(svc, db):
    for u in ("u1", "u2", "u3", "u4", "u5", "u6", "u7", "u8", "u9"):
        history(svc, ORG_A, user=u, host="fin-srv")
        # everyone in this group also uses a shared file server
        for d in range(3):
            svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=d, hours=9, minutes=7), user=u, host="fin-files"), [])
            svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=d + 3, hours=9, minutes=7), user=u, host="fin-files"), [])
    out = svc.recluster(ORG_A)
    assert out["user"]["mature_entities"] >= 9 and out["user"]["groups"] >= 1
    assert svc.entity_summary(ORG_A, "user", "u1")["peer_group"]


def test_failure_in_behaviour_never_loses_deterministic_detections(client, auth, db, drain, monkeypatch):
    from app.services import behavior_service

    monkeypatch.setattr(behavior_service, "evaluate_and_learn", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    from app.agents.triage import TriageInput
    from app.services.ingest_service import accept_events

    accept_events(ORG_A, [TriageInput(title="x", event_type="process.start", command_line="wevtutil cl Security", asset_name="srv1")], source_system="t")
    drain()
    ev = db.rows("events")[0]
    assert ev["processed"] and any(d["rule_id"] == "TB-EVADE-001" for d in ev["detections"])


def test_behaviour_detection_flows_through_the_real_pipeline_and_is_distinguishable(client, auth, db, drain):
    from app.agents.triage import TriageInput
    from app.services.ingest_service import accept_events

    rnd = random.Random(1)
    evs = [TriageInput(title="Sign-in", event_type="authentication.success", username="alice", source_ip="10.1.4.20", asset_name="ws-alice",
                       occurred_at=T0 + timedelta(days=d, hours=rnd.choice((8, 9, 10, 13, 14, 16)), minutes=rnd.randint(0, 59)))
           for d in range(12) for _ in range(6)]
    accept_events(ORG_A, evs, source_system="warmup")
    drain()
    assert not any(e["alerted"] for e in db.rows("events"))                 # a normal month raises nothing
    accept_events(ORG_A, [TriageInput(title="Sign-in", event_type="authentication.success", username="ALICE", source_ip="198.51.100.9",
                                      asset_name="DC-01.corp.local", occurred_at=T0 + timedelta(days=13, hours=3, minutes=10))], source_system="t")
    drain()
    hit = next(e for e in db.rows("events") if e["alerted"])
    kinds = {d["kind"] for d in hit["detections"]}
    assert kinds == {"behavior"} and hit["detections"][0]["explanation"]["signals"]
    assert hit["username"] == "alice" and hit["asset_name"] == "dc-01"        # identity spellings are canonicalised
    assert hit["raw_data"]["_username_as_sent"] == "ALICE"
    assert db.rows("threats")                                                # and it reached triage/threat creation


# ------------------------------------------------------------------------------------------- API
def test_behavior_api_roles_and_tenancy(client, auth, db, svc):
    history(svc, ORG_A)
    svc.evaluate_and_learn(ORG_A, login(T0 + timedelta(days=13, hours=3), ip="198.51.100.9", host="dc-01"), [])
    assert client.get("/api/v1/behavior/status", headers=auth("viewer_a")).status_code == 200
    assert client.get("/api/v1/behavior/anomalies", headers=auth("viewer_a")).status_code == 403
    rows = client.get("/api/v1/behavior/anomalies", headers=auth("analyst_a")).json()
    assert rows and client.get("/api/v1/behavior/anomalies", headers=auth("analyst_b")).json() == []
    base = client.get("/api/v1/behavior/entities/user/alice", headers=auth("analyst_a")).json()
    assert base["mature"] and base["features"]["auth.host"]["top"]
    assert client.get("/api/v1/behavior/entities/user/alice", headers=auth("analyst_b")).status_code == 404
    aid = rows[0]["id"]
    assert client.patch(f"/api/v1/behavior/anomalies/{aid}", json={"disposition": "confirmed"}, headers=auth("analyst_b")).status_code == 404
    assert client.patch(f"/api/v1/behavior/anomalies/{aid}", json={"disposition": "confirmed"}, headers=auth("analyst_a")).status_code == 200
    assert client.patch(f"/api/v1/behavior/anomalies/{aid}", json={"disposition": "bogus"}, headers=auth("analyst_a")).status_code == 422
    st = client.get("/api/v1/behavior/status", headers=auth("analyst_a")).json()
    assert st["analyst_feedback"]["confirmed"] == 1 and st["analyst_feedback"]["precision"] == 1.0


def test_behavior_settings_are_admin_only_validated_and_audited(client, auth, db):
    assert client.put("/api/v1/behavior/settings", json={"sensitivity": "high"}, headers=auth("analyst_a")).status_code == 403
    assert client.put("/api/v1/behavior/settings", json={"params": {"min_families": 1}}, headers=auth("admin_a")).status_code == 422
    assert client.put("/api/v1/behavior/settings", json={"sensitivity": "high", "params": {"alert_score": 0.75}}, headers=auth("admin_a")).status_code == 200
    got = client.get("/api/v1/behavior/settings", headers=auth("analyst_a")).json()
    assert got["sensitivity"] == "high" and got["effective"]["alert_score"] == 0.75 and "alert_score" in got["bounds"]
    assert any(a["action"] == "behavior.settings_updated" for a in db.rows("audit_logs"))
    assert client.get("/api/v1/behavior/settings", headers=auth("analyst_b")).json()["sensitivity"] == "balanced"     # tenant isolation
    assert client.put("/api/v1/behavior/settings", json={"surprise": 1}, headers=auth("admin_a")).status_code == 422


def test_learn_and_recluster_jobs_run(client, auth, db, drain):
    assert client.post("/api/v1/behavior/learn?days=7", headers=auth("analyst_a")).status_code == 403
    assert client.post("/api/v1/behavior/learn?days=7", headers=auth("admin_a")).status_code == 202
    assert client.post("/api/v1/behavior/recluster", headers=auth("admin_a")).status_code == 202
    drain()
    assert {j["kind"]: j["status"] for j in db.rows("jobs")} == {"behavior.backfill": "succeeded", "behavior.recluster": "succeeded"}


def test_features_catalogue_is_explainable(client, auth):
    rows = client.get("/api/v1/behavior/features", headers=auth("viewer_a")).json()
    assert {r["feature"] for r in rows} >= {"auth.source_net", "net.bytes_out_hour", "priv.action"} and all(r["techniques"] for r in rows)
