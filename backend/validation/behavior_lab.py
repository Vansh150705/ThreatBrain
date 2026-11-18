"""Behavioural-analytics validation: scenarios with a synthetic *history* (to learn from) and *test events* (to judge).

Every scenario is deterministic (seeded from its id). Two modes mirror the rest of the lab:
  engine    the pure statistical engine (app.behavior.engine), in-memory states
  pipeline  the real service (app.services.behavior_service) on the in-memory PostgREST stand-in: history is learned through
            the product's own history-backfill path, test events through evaluate_and_learn (baselines, peers, cooldown,
            suppression, budget all active)
Nothing is executed; all events are data.
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from datetime import UTC, datetime, timedelta
from typing import Any

T_END = datetime(2026, 4, 15, 0, 0, tzinfo=UTC)


def _seed(sid: str) -> int:
    return int(hashlib.sha256(sid.encode()).hexdigest()[:12], 16)


def _iso(ts: datetime) -> str:
    return ts.isoformat()


# ------------------------------------------------------------------------------------------ generators
def _hours(spec: dict[str, Any]) -> list[int]:
    h = spec.get("hours") or list(range(8, 18))
    return list(range(h[0], h[1] + 1)) if spec.get("hours_range") else list(h)


def gen_history(specs: list[dict[str, Any]], sid: str) -> list[dict[str, Any]]:
    rnd = random.Random(_seed(sid))
    out: list[dict[str, Any]] = []
    for sp in specs:
        g = sp["gen"]
        days = int(sp.get("days", 14))
        if g == "logins":
            users = sp.get("users") or [sp["user"]]
            if isinstance(users, int):
                users = [f"{sp.get('user_prefix', 'peer')}{i + 1:02d}" for i in range(users)]
            for u in users:
                for d in range(days):
                    day = T_END - timedelta(days=days - d)
                    if sp.get("weekdays_only") and day.weekday() >= 5:
                        continue
                    for _ in range(int(sp.get("per_day", 6))):
                        ts = day.replace(hour=rnd.choice(_hours(sp)), minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
                        out.append({"event_type": "authentication.success", "username": u, "source_ip": rnd.choice(sp.get("nets", ["10.1.4.20"])),
                                    "asset_name": rnd.choice(sp.get("hosts", ["ws-" + u])), "observed_at": _iso(ts), "raw_data": {}})
        elif g == "flows":
            host = sp["host"]
            per_hour = sp.get("per_hour", [1, 3])
            for d in range(days):
                day = T_END - timedelta(days=days - d)
                for h in sp.get("hours", range(24)):
                    for _ in range(rnd.randint(*per_hour)):
                        sent = rnd.lognormvariate(math.log(sp.get("bytes_median", 40_000)), sp.get("sigma", 0.6))
                        if sp.get("spike_prob") and rnd.random() < sp["spike_prob"]:
                            sent *= sp.get("spike_mult", 8)
                        ts = day.replace(hour=h, minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
                        out.append({"event_type": "network.flow", "asset_name": host, "source_ip": "10.0.2.9",
                                    "destination_ip": rnd.choice(sp.get("dests", ["198.51.100.20"])), "destination_port": rnd.choice(sp.get("ports", [443])),
                                    "observed_at": _iso(ts), "raw_data": {"bytes_out": int(sent)}})
                if sp.get("nightly_mb"):      # a recurring backup window
                    out.append({"event_type": "network.flow", "asset_name": host, "source_ip": "10.0.2.9", "destination_ip": sp.get("backup_dest", sp.get("dests", ["198.51.100.20"])[0]),
                                "destination_port": 443, "observed_at": _iso(day.replace(hour=2, minute=rnd.randint(0, 40))), "raw_data": {"bytes_out": int(sp["nightly_mb"] * 1e6)}})
        elif g == "procs":
            host = sp["host"]
            names = sp["names"]
            for d in range(days):
                day = T_END - timedelta(days=days - d)
                for _ in range(int(sp.get("per_day", 40))):
                    n = rnd.choice(names)
                    ts = day.replace(hour=rnd.randint(0, 23), minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
                    out.append({"event_type": "process.start", "asset_name": host, "process_name": n, "observed_at": _iso(ts),
                                "raw_data": {"parent_process": sp.get("parent", "systemd"), "process_path": f"/usr/bin/{n}"}})
        elif g == "cloud":
            user = sp["user"]
            for d in range(days):
                day = T_END - timedelta(days=days - d)
                for _ in range(int(sp.get("per_day", 8))):
                    action, source = rnd.choice(sp["actions"])
                    raw = {"eventName": action, "eventSource": source}
                    if sp.get("resources"):
                        raw["bucket"] = rnd.choice(sp["resources"])
                    ts = day.replace(hour=rnd.choice(_hours(sp)), minute=rnd.randint(0, 59), second=rnd.randint(0, 59))
                    out.append({"event_type": "cloud.audit", "username": user, "source_ip": sp.get("ip", "10.0.0.8"), "observed_at": _iso(ts), "raw_data": raw})
        else:
            raise ValueError(f"unknown generator {g}")
    out.sort(key=lambda e: e["observed_at"])
    return out


def gen_tests(tests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for t in tests:
        t = dict(t)
        at_h = float(t.pop("at_h", 0))
        rep = t.pop("repeat", 1)
        step = float(t.pop("step_min", 1))
        vary = t.pop("vary", None)     # {field: [values...]} cycled across repeats (e.g. different hosts)
        for i in range(int(rep)):
            ev = {k: (dict(v) if isinstance(v, dict) else v) for k, v in t.items()}
            if vary:
                for field, vals in vary.items():
                    ev[field] = vals[i % len(vals)]
            ev["observed_at"] = _iso(T_END + timedelta(hours=at_h, minutes=i * step))
            ev.setdefault("raw_data", {})
            out.append(ev)
    out.sort(key=lambda e: e["observed_at"])
    return out


# ------------------------------------------------------------------------------------------ evaluation
def _group(events: list[dict[str, Any]]):
    from app.behavior import features
    for ev in events:
        yield ev, features.extract(ev)


def run_engine_scenario(sc: dict[str, Any], cfg=None) -> dict[str, Any]:
    from app.behavior import config as bconfig
    from app.behavior import engine, features

    cfg = cfg or bconfig.build(sc.get("sensitivity", "balanced"), sc.get("params"))
    states: dict[tuple[str, str], dict[str, Any]] = {}
    pops: dict[str, engine.PopulationView] = {"user": engine.PopulationView(), "host": engine.PopulationView()}
    for _ev, obs in _group(gen_history(sc.get("history", []), sc["id"])):
        by: dict[tuple[str, str], list] = {}
        for o in obs:
            by.setdefault((o.etype, o.eid), []).append(o)
        for key, olist in by.items():
            st = states.setdefault(key, engine.new_state())
            res = engine.analyze(st, olist, cfg, None, learn=True)
            engine.apply_delta(pops[key[0]], res.delta)
    alerts, anomalies, first_alert_h = [], [], None
    t0 = time.perf_counter()
    last_alert: dict[tuple[str, str, str], float] = {}
    for ev in gen_tests(sc.get("test", [])):
        obs = features.extract(ev)
        by = {}
        for o in obs:
            by.setdefault((o.etype, o.eid), []).append(o)
        ts = features.event_time(ev)
        for key, olist in by.items():
            st = states.setdefault(key, engine.new_state())
            res = engine.analyze(st, olist, cfg, pops[key[0]] if pops[key[0]].mature >= cfg.peer_min_entities else None, learn=True)
            engine.apply_delta(pops[key[0]], res.delta)
            dec = engine.decide(st, res.anomalies, cfg, ts) if res.anomalies else None
            engine.remember(st, res.anomalies)
            anomalies += [a.public() | {"entity": key[1]} for a in res.anomalies]
            if dec and dec.alert:
                fam = tuple(sorted(f for f in dec.families))
                if all(ts - last_alert.get((key[0], key[1], f), -1e12) < cfg.cooldown_hours * 3600 for f in fam):
                    continue
                engine.mark_alerted(st, dec.contributing, ts)
                for f in fam:
                    last_alert[(key[0], key[1], f)] = ts
                alerts.append({"entity": key[1], "risk": round(dec.risk, 3), "families": sorted(dec.families), "reason": dec.reason})
                first_alert_h = first_alert_h if first_alert_h is not None else round((ts - T_END.timestamp()) / 3600, 2)
    return {"alerts": alerts, "anomalies": anomalies, "ms": round((time.perf_counter() - t0) * 1000, 1), "first_alert_h": first_alert_h}


def run_service_scenario(sc: dict[str, Any]) -> dict[str, Any]:
    from app.services import behavior_service as svc
    from app.services import supabase_client
    from tests import conftest as c
    from tests.fake_supabase import FakeSupabase

    fake = FakeSupabase()
    supabase_client.get_supabase_admin.cache_clear()
    supabase_client.create_client = lambda *a, **k: fake   # type: ignore[assignment]
    c.seed(fake)
    svc.invalidate()
    org = c.ORG_A
    if sc.get("sensitivity") or sc.get("params"):
        svc.update_settings(org, enabled=True, sensitivity=sc.get("sensitivity"), params=sc.get("params"), user_id=None)
    hist = gen_history(sc.get("history", []), sc["id"])
    for i in range(0, len(hist), 400):
        svc.learn_batch(org, hist[i:i + 400])
    svc.recluster(org)
    alerts, first_alert_h = [], None
    t0 = time.perf_counter()
    for ev in gen_tests(sc.get("test", [])):
        hits = svc.evaluate_and_learn(org, ev, [])
        for h in hits:
            alerts.append({"entity": h.explanation["entity"]["id"], "risk": h.explanation["risk"], "families": sorted(h.explanation["families"]),
                           "reason": h.explanation["decision"], "rule": h.rule_id, "severity": h.severity})
            if first_alert_h is None:
                first_alert_h = round((datetime.fromisoformat(ev["observed_at"]) - T_END).total_seconds() / 3600, 2)
    anomalies = [{"feature": r["feature"], "score": r["score"], "entity": r["entity_id"], "suppressed": r["suppressed_reason"]} for r in fake.rows("behavior_anomalies")]
    return {"alerts": alerts, "anomalies": anomalies, "ms": round((time.perf_counter() - t0) * 1000, 1), "first_alert_h": first_alert_h}


def judge(sc: dict[str, Any], res: dict[str, Any]) -> dict[str, Any]:
    alerted = bool(res["alerts"])
    label = sc["label"]
    return {"id": sc["id"], "name": sc["name"], "label": label, "alerted": alerted, "alerts": len(res["alerts"]),
            "passed": alerted if label == "attack" else not alerted,
            "families": sorted({f for a in res["alerts"] for f in a["families"]}),
            "anomalies_recorded": len(res["anomalies"]), "first_alert_after_h": res["first_alert_h"], "ms": res["ms"],
            **({"known_gap": True, "gap_reason": sc.get("gap_reason", "")} if sc.get("known_gap") else {})}


# ------------------------------------------------------------------------------------------ alert-volume simulation
def simulate_noise(entities: int = 120, days: int = 45, warmup_days: int = 14, seed: int = 11, cfg=None) -> dict[str, Any]:
    """A month and a half of ordinary organisational variation: people travel, take new projects, shift hours; hosts get
    deployments, new CDNs, backup windows and occasional legitimate spikes. NOTHING in here is malicious, so every alert
    is a false positive. Reported as alerts per 100 entity-days after the warm-up period."""
    from app.behavior import config as bconfig
    from app.behavior import engine, features

    cfg = cfg or bconfig.build()
    rnd = random.Random(seed)
    n_dept = max(4, entities // 12)
    dept_hosts = {d: [f"d{d}-srv{i}" for i in range(4)] for d in range(n_dept)}
    users = []
    for i in range(entities):
        d = i % n_dept
        users.append({"id": f"user{i:03d}", "dept": d, "hosts": rnd.sample(dept_hosts[d], 3), "net": f"10.{d}.{rnd.randint(1, 50)}.0",
                      "home": f"10.200.{rnd.randint(1, 250)}.0", "shift": rnd.choice([7, 8, 9, 10]), "travel_until": -1, "shifted_until": -1, "shift_delta": 0})
    hosts = [{"id": f"srv{i:02d}", "median": rnd.choice([20_000, 60_000, 150_000]), "procs": [f"p{j}" for j in range(8)], "dests": [f"198.51.{j}.0" for j in range(1, 4)]} for i in range(max(10, entities // 6))]
    states: dict[tuple[str, str], dict[str, Any]] = {}
    pop = {"user": engine.PopulationView(), "host": engine.PopulationView()}
    alerts = 0
    entity_days = 0
    by_family: dict[str, int] = {}
    last_alert: dict[tuple[str, str, str], float] = {}
    new_dept_host_day = {d: rnd.randint(warmup_days + 3, days - 3) for d in range(n_dept) if rnd.random() < 0.4}

    def feed(ev: dict[str, Any], count: bool, day: int) -> None:
        nonlocal alerts
        by: dict[tuple[str, str], list] = {}
        for o in features.extract(ev):
            by.setdefault((o.etype, o.eid), []).append(o)
        ts = features.event_time(ev)
        for key, olist in by.items():
            st = states.setdefault(key, engine.new_state())
            res = engine.analyze(st, olist, cfg, pop[key[0]] if pop[key[0]].mature >= cfg.peer_min_entities else None, learn=True)
            engine.apply_delta(pop[key[0]], res.delta)
            dec = engine.decide(st, res.anomalies, cfg, ts) if res.anomalies else None
            engine.remember(st, res.anomalies)
            if count and dec and dec.alert:
                fam = tuple(sorted(dec.families))
                if all(ts - last_alert.get((key[0], key[1], f), -1e12) < cfg.cooldown_hours * 3600 for f in fam):
                    continue
                engine.mark_alerted(st, dec.contributing, ts)
                for f in fam:
                    last_alert[(key[0], key[1], f)] = ts
                alerts += 1
                for f in fam:
                    by_family[f] = by_family.get(f, 0) + 1

    for day in range(days):
        base = T_END - timedelta(days=days - day)
        count = day >= warmup_days
        for d, dd in new_dept_host_day.items():
            if day == dd:     # a department adopts a new shared system: everyone in it starts using it
                dept_hosts[d].append(f"d{d}-newapp")
        for u in users:
            if rnd.random() < 0.02 and u["travel_until"] < day:
                u["travel_until"] = day + rnd.randint(2, 5)
            if rnd.random() < 0.012 and u["shifted_until"] < day:
                u["shifted_until"] = day + 10
                u["shift_delta"] = rnd.choice([-3, 3, 5])
            if base.weekday() >= 5 and rnd.random() < 0.8:
                continue
            hosts_pool = u["hosts"] + ([f"d{u['dept']}-newapp"] if f"d{u['dept']}-newapp" in dept_hosts[u["dept"]] and rnd.random() < 0.7 else [])
            if rnd.random() < 0.03:
                hosts_pool = hosts_pool + [rnd.choice(sum(dept_hosts.values(), []))]
            net = u["home"] if u["travel_until"] >= day and rnd.random() < 0.7 else u["net"]
            start = u["shift"] + (u["shift_delta"] if u["shifted_until"] >= day else 0)
            for _ in range(rnd.randint(4, 9)):
                h = min(23, max(0, start + rnd.randint(0, 8)))
                if rnd.random() < 0.04:
                    h = rnd.choice([21, 22, 23, 5, 6])
                ts = base.replace(hour=h, minute=rnd.randint(0, 59))
                feed({"event_type": "authentication.success", "username": u["id"], "source_ip": net.rsplit(".", 1)[0] + ".7", "asset_name": rnd.choice(hosts_pool),
                      "observed_at": _iso(ts), "raw_data": {}}, count, day)
            if count:
                entity_days += 1
        for hst in hosts:
            if rnd.random() < 0.02:
                hst["procs"].append(f"deploy{day}")        # a deployment adds a binary
            for hr in range(24):
                for _ in range(rnd.randint(1, 3)):
                    sent = rnd.lognormvariate(math.log(hst["median"]), 0.7) * (8 if rnd.random() < 0.01 else 1)
                    dest = rnd.choice(hst["dests"]) if rnd.random() > 0.02 else f"198.51.{rnd.randint(10, 200)}.0"
                    feed({"event_type": "network.flow", "asset_name": hst["id"], "source_ip": "10.0.2.9", "destination_ip": dest.rsplit(".", 1)[0] + ".9",
                          "destination_port": 443, "observed_at": _iso(base.replace(hour=hr, minute=rnd.randint(0, 59))), "raw_data": {"bytes_out": int(sent)}}, count, day)
                if hr % 3 == 0:
                    n = rnd.choice(hst["procs"][-3:] if rnd.random() < 0.05 else hst["procs"])
                    feed({"event_type": "process.start", "asset_name": hst["id"], "process_name": n, "observed_at": _iso(base.replace(hour=hr, minute=rnd.randint(0, 59))),
                          "raw_data": {"parent_process": "systemd", "process_path": f"/usr/bin/{n}"}}, count, day)
            if count:
                entity_days += 1
    return {"entities": len(users) + len(hosts), "days": days, "warmup_days": warmup_days, "entity_days": entity_days, "alerts": alerts,
            "alerts_per_100_entity_days": round(100 * alerts / max(1, entity_days), 3), "by_family": by_family, "seed": seed}
