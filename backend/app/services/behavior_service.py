"""Behavioural analytics service: baselines in PostgreSQL, scored anomalies, alert budget, analyst feedback.

Concurrency: many workers process events at once. A profile row carries a ``version``; writers compare-and-swap on it and
retry (re-reading the fresher baseline) on conflict, so two workers can never silently overwrite each other's learning.

Failure isolation: callers (``event_processor``) treat any exception here as "behaviour unavailable for this event" - the
deterministic detections already computed are never lost because baselines could not be read.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from postgrest.exceptions import APIError

from app.behavior import config as bconfig
from app.behavior import engine, features, model
from app.behavior.features import FAMILY_CODE, FEATURES
from app.core import metrics
from app.core.logging import get_logger
from app.detection.attack_catalog import tactics_for
from app.detection.engine import RuleHit
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)

SETTINGS_TTL = 30.0
POP_TTL = 20.0
CAS_ATTEMPTS = 4
_lock = threading.Lock()
_settings_cache: dict[str, tuple[float, bool, bconfig.BehaviorConfig, dict[str, Any]]] = {}
_pop_cache: dict[tuple[str, str, str], tuple[float, engine.PopulationView]] = {}

behavior_anomalies, behavior_alerts = metrics.behavior_anomalies, metrics.behavior_alerts
behavior_suppressed, behavior_errors = metrics.behavior_suppressed, metrics.behavior_errors
behavior_conflicts, behavior_latency = metrics.behavior_conflicts, metrics.behavior_latency


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat()


# ------------------------------------------------------------------------------------------ settings
def invalidate(org_id: str | None = None) -> None:
    with _lock:
        if org_id is None:
            _settings_cache.clear()
            _pop_cache.clear()
        else:
            _settings_cache.pop(str(org_id), None)
            for k in [k for k in _pop_cache if k[0] == str(org_id)]:
                _pop_cache.pop(k, None)


def get_settings_row(org_id: str) -> dict[str, Any]:
    rows = get_supabase_admin().table("behavior_settings").select("*").eq("organization_id", org_id).limit(1).execute().data
    return rows[0] if rows else {"organization_id": org_id, "enabled": True, "sensitivity": "balanced", "params": {}}


def _settings(org_id: str) -> tuple[bool, bconfig.BehaviorConfig]:
    now = time.monotonic()
    with _lock:
        hit = _settings_cache.get(org_id)
        if hit and now - hit[0] < SETTINGS_TTL:
            return hit[1], hit[2]
    row = get_settings_row(org_id)
    try:
        cfg = bconfig.build(row.get("sensitivity") or "balanced", row.get("params") or {})
    except bconfig.ConfigError:        # a bad stored override must not disable or crash detection: fall back to defaults
        log.warning("behavior_bad_params", org_id=org_id)
        cfg = bconfig.build(row.get("sensitivity") or "balanced")
    enabled = bool(row.get("enabled", True))
    with _lock:
        _settings_cache[org_id] = (now, enabled, cfg, row)
    return enabled, cfg


def update_settings(org_id: str, *, enabled: bool | None, sensitivity: str | None, params: dict[str, Any] | None, user_id: str | None) -> dict[str, Any]:
    if sensitivity is not None and sensitivity not in ("low", "balanced", "high"):
        raise bconfig.ConfigError("sensitivity must be low, balanced or high")
    clean = bconfig.validate_params(params) if params is not None else None
    cur = get_settings_row(org_id)
    row = {
        "organization_id": org_id,
        "enabled": cur["enabled"] if enabled is None else enabled,
        "sensitivity": sensitivity or cur["sensitivity"],
        "params": cur.get("params") or {} if clean is None else clean,
        "updated_by": user_id, "updated_at": _now_iso(),
    }
    get_supabase_admin().table("behavior_settings").upsert(row, on_conflict="organization_id").execute()
    invalidate(org_id)
    return row


# ------------------------------------------------------------------------------------------ profile store
def load_profile(org_id: str, etype: str, eid: str) -> tuple[dict[str, Any], int]:
    rows = (get_supabase_admin().table("behavior_profiles").select("state,version")
            .eq("organization_id", org_id).eq("entity_type", etype).eq("entity_id", eid).limit(1).execute().data)
    if not rows:
        return engine.new_state(), 0
    return rows[0]["state"] or engine.new_state(), int(rows[0]["version"])


def save_profile(org_id: str, etype: str, eid: str, state: dict[str, Any], version: int) -> bool:
    """Compare-and-swap. False on conflict (someone else wrote first); the caller re-reads and retries."""
    client = get_supabase_admin()
    meta = state["meta"]
    body = {"state": state, "event_count": meta["events"],
            "first_seen": _iso(meta["first"]) if meta["first"] else None,
            "last_seen": _iso(meta["last"]) if meta["last"] else None, "updated_at": _now_iso()}
    if version == 0:
        try:
            client.table("behavior_profiles").insert({"organization_id": org_id, "entity_type": etype, "entity_id": eid,
                                                      "version": 1, **body}).execute()
            return True
        except APIError as exc:
            if getattr(exc, "code", "") == "23505" or "duplicate" in str(exc).lower():
                return False
            raise
    won = (client.table("behavior_profiles").update({**body, "version": version + 1})
           .eq("organization_id", org_id).eq("entity_type", etype).eq("entity_id", eid).eq("version", version)
           .execute().data)
    return bool(won)


def _population(org_id: str, etype: str, peer: str | None) -> engine.PopulationView | None:
    """Prefer the entity's peer group when it is large enough, else the whole tenant."""
    cfg_min = 3
    for scope_id, label in (((f"{etype}:pg:{peer}", f"peer group {peer}") if peer else (None, "")), ((etype, "tenant"))):
        if not scope_id:
            continue
        key = (org_id, etype, scope_id)
        now = time.monotonic()
        with _lock:
            hit = _pop_cache.get(key)
        if hit and now - hit[0] < POP_TTL:
            view = hit[1]
        else:
            rows = (get_supabase_admin().table("behavior_profiles").select("state")
                    .eq("organization_id", org_id).eq("entity_type", "population").eq("entity_id", scope_id).limit(1).execute().data)
            st = (rows[0]["state"] if rows else {}) or {}
            view = engine.PopulationView(mature=int(st.get("mature", 0)), holders=st.get("holders", {}), scope=label,
                                         recent=st.get("recent", {}))
            with _lock:
                _pop_cache[key] = (now, view)
        if view.mature >= cfg_min:
            return view
    return None


def _apply_population(org_id: str, etype: str, peer: str | None, delta: engine.PopDelta) -> None:
    if not delta.mature and not delta.holders and not delta.first_seen:
        return
    client = get_supabase_admin()
    for scope_id in ([etype] + ([f"{etype}:pg:{peer}"] if peer else [])):
        for _ in range(CAS_ATTEMPTS):
            rows = (client.table("behavior_profiles").select("state,version").eq("organization_id", org_id)
                    .eq("entity_type", "population").eq("entity_id", scope_id).limit(1).execute().data)
            st = (rows[0]["state"] if rows else None) or {"mature": 0, "holders": {}}
            version = int(rows[0]["version"]) if rows else 0
            st["mature"] = int(st.get("mature", 0)) + delta.mature
            for (feature, key), n in delta.holders.items():
                bucket = st["holders"].setdefault(feature, {})
                bucket[key] = bucket.get(key, 0) + n
                if len(bucket) > 2000:           # bound: drop the rarest values
                    for k, _v in sorted(bucket.items(), key=lambda kv: kv[1])[: len(bucket) - 2000]:
                        bucket.pop(k, None)
            for (feature, key), ts in delta.first_seen.items():
                recent = st.setdefault("recent", {}).setdefault(feature, {})
                rec = recent.setdefault(key, [0, 0.0])
                rec[0] += 1
                rec[1] = max(rec[1], ts)
                if len(recent) > 2000:                    # bound: forget the stalest first sights
                    for k, _v in sorted(recent.items(), key=lambda kv: kv[1][1])[: len(recent) - 2000]:
                        recent.pop(k, None)
            body = {"state": st, "updated_at": _now_iso(), "last_seen": _now_iso()}
            try:
                if version == 0:
                    client.table("behavior_profiles").insert({"organization_id": org_id, "entity_type": "population", "entity_id": scope_id, "version": 1, **body}).execute()
                    break
                if client.table("behavior_profiles").update({**body, "version": version + 1}).eq("organization_id", org_id) \
                        .eq("entity_type", "population").eq("entity_id", scope_id).eq("version", version).execute().data:
                    break
            except APIError:
                pass
            behavior_conflicts.inc()
    with _lock:
        for k in [k for k in _pop_cache if k[0] == org_id]:
            _pop_cache.pop(k, None)


# ------------------------------------------------------------------------------------------ suppressions & budget
def _suppressions(org_id: str) -> list[dict[str, Any]]:
    now = _now_iso()
    rows = get_supabase_admin().table("behavior_suppressions").select("*").eq("organization_id", org_id).execute().data or []
    return [r for r in rows if not r.get("expires_at") or str(r["expires_at"]) > now]


def _suppressed_by(rules: list[dict[str, Any]], etype: str, eid: str, a: engine.Anomaly) -> dict[str, Any] | None:
    for r in rules:
        if all(r.get(f, "*") in ("*", v) for f, v in (("entity_type", etype), ("entity_id", eid), ("feature", a.feature), ("value_key", a.key))):
            return r
    return None


def _org_alerts_last_hour(org_id: str, now: float) -> int:
    since = _iso(now - 3600)
    rows = (get_supabase_admin().table("behavior_anomalies").select("id").eq("organization_id", org_id)
            .eq("alerted", True).gte("observed_at", since).limit(2000).execute().data or [])
    return len(rows)


# ------------------------------------------------------------------------------------------ evaluation
def _severity(risk: float) -> str:
    return "high" if risk >= 0.9 else "medium" if risk >= 0.8 else "low"


def _hit(decision: engine.Decision, etype: str, eid: str) -> RuleHit:
    ranked = sorted(decision.contributing, key=lambda a: -a.score)
    top = ranked[0]
    techniques = list(dict.fromkeys(t for a in ranked for t in FEATURES[a.feature].techniques))
    families = sorted(decision.families, key=lambda f: -decision.families[f])
    return RuleHit(
        rule_id=FAMILY_CODE[top.family] if len(families) == 1 else "TB-UEBA-009",
        name=("Unusual behaviour: " + FEATURES[top.feature].title) if len(families) == 1
        else f"Unusual behaviour across {len(families)} independent signals for {eid}",
        severity=_severity(decision.risk), confidence=min(85, int(decision.risk * 90)),
        tactics=tactics_for(techniques), techniques=techniques, tags=["behavior", "ueba", *families],
        matched_fields=sorted({a.feature for a in ranked}), kind="behavior",
        dedupe_key=f"ueba:{etype}:{eid}:{top.family}",
        explanation={"entity": {"type": etype, "id": eid}, "risk": round(decision.risk, 3), "decision": decision.reason,
                     "families": {k: round(v, 3) for k, v in decision.families.items()},
                     "signals": [a.public() for a in ranked[:6]],
                     "note": "Statistical deviation from this tenant's own baseline - not a signature match. Review before acting."},
    )


def _rebuild_hits(prior: list[dict[str, Any]]) -> list[RuleHit]:
    out: dict[str, RuleHit] = {}
    for row in prior:
        stored = (row.get("explanation") or {}).get("_hit")
        if row.get("alerted") and stored and stored.get("dedupe_key") not in out:
            out[stored["dedupe_key"]] = RuleHit(**{k: v for k, v in stored.items() if k in RuleHit.__dataclass_fields__})
    return list(out.values())


def evaluate_and_learn(org_id: str, event: dict[str, Any], deterministic_hits: list[RuleHit] | None = None) -> list[RuleHit]:
    """Score the event against the tenant's baselines, learn from it when it is clean, and return behaviour detections."""
    org_id = str(org_id)
    enabled, cfg = _settings(org_id)
    if not enabled:
        return []
    obs = features.extract(event)
    if not obs:
        return []
    if event.get("id"):    # redelivered job: the event was already evaluated; return what it produced instead of learning twice
        prior = (get_supabase_admin().table("behavior_anomalies").select("alerted,explanation").eq("organization_id", org_id)
                 .eq("event_id", str(event["id"])).limit(50).execute().data or [])
        if prior:
            return _rebuild_hits(prior)
    learn = not deterministic_hits          # attacker activity must never shape the baseline
    groups: dict[tuple[str, str], list[features.Obs]] = {}
    for o in obs:
        groups.setdefault((o.etype, o.eid), []).append(o)
    ts = obs[0].ts
    rules: list[dict[str, Any]] | None = None
    hits: list[RuleHit] = []
    rows: list[dict[str, Any]] = []
    t0 = time.perf_counter()
    for (etype, eid), olist in groups.items():
        for attempt in range(CAS_ATTEMPTS):
            state, version = load_profile(org_id, etype, eid)
            pop = _population(org_id, etype, state["meta"].get("peer"))
            res = engine.analyze(state, olist, cfg, pop, learn=learn)
            decision = engine.decide(state, res.anomalies, cfg, ts) if res.anomalies else None
            suppressed: dict[str, str] = {}
            alert = bool(decision and decision.alert)
            if alert:
                rules = rules if rules is not None else _suppressions(org_id)
                fam = {a.family for a in decision.contributing}
                recent_alerts = [a for a in state["alerts"] if a[0] >= ts - cfg.cooldown_hours * 3600]
                matched = [(a, _suppressed_by(rules, etype, eid, a)) for a in decision.contributing]
                if all(m for _a, m in matched):
                    alert, why = False, "suppression"
                elif any(a[1] in fam and a[0] >= ts - cfg.cooldown_hours * 3600 for a in state["alerts"]):
                    alert, why = False, "cooldown"
                elif len([a for a in recent_alerts if a[0] >= ts - 86400]) >= cfg.budget_per_entity_day:
                    alert, why = False, "budget"
                elif _org_alerts_last_hour(org_id, ts) >= cfg.budget_per_org_hour:
                    alert, why = False, "budget"
                else:
                    why = ""
                if why:
                    behavior_suppressed.inc(reason=why)
                    for a in decision.contributing:
                        suppressed[f"{a.feature}|{a.key}"] = why
                if alert:
                    state["alerts"] = (recent_alerts + [[ts, f] for f in fam])[-30:]
                    engine.mark_alerted(state, decision.contributing, ts)
            if res.anomalies:
                engine.remember(state, res.anomalies)
            changed = learn or bool(res.anomalies)
            if changed and not save_profile(org_id, etype, eid, state, version):
                behavior_conflicts.inc()
                if attempt == CAS_ATTEMPTS - 1:
                    behavior_errors.inc()
                    log.warning("behavior_cas_exhausted", entity=eid)
                    break
                continue
            if learn:
                _apply_population(org_id, etype, state["meta"].get("peer"), res.delta)
            break
        else:      # pragma: no cover
            continue
        hit = _hit(decision, etype, eid) if alert and decision else None
        for a in res.anomalies:
            behavior_anomalies.inc(feature=a.feature)
            in_alert = bool(alert and decision and a in decision.contributing)
            rows.append({
                "organization_id": org_id, "entity_type": etype, "entity_id": eid, "event_id": event.get("id"),
                "feature": a.feature, "value_key": a.key[:200], "score": round(a.score, 3), "severity": _severity(a.score),
                "explanation": {**a.explanation, **({"_hit": hit.as_dict() | {"dedupe_key": hit.dedupe_key}} if in_alert and hit else {})},
                "alerted": in_alert,
                "suppressed_reason": suppressed.get(f"{a.feature}|{a.key}"), "observed_at": _iso(a.ts),
            })
        if hit:
            behavior_alerts.inc(family=",".join(sorted({a.family for a in decision.contributing}))[:60])
            hits.append(hit)
    if rows:
        get_supabase_admin().table("behavior_anomalies").insert(rows).execute()
    behavior_latency.observe(time.perf_counter() - t0)
    return hits



# ------------------------------------------------------------------------------------------ analyst interface
def list_anomalies(org_id: str, *, entity_id: str | None = None, entity_type: str | None = None, feature: str | None = None,
                   alerted: bool | None = None, disposition: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    q = get_supabase_admin().table("behavior_anomalies").select("*").eq("organization_id", org_id)
    if entity_id:
        q = q.eq("entity_id", entity_id)
    if entity_type:
        q = q.eq("entity_type", entity_type)
    if feature:
        q = q.eq("feature", feature)
    if alerted is not None:
        q = q.eq("alerted", alerted)
    if disposition:
        q = q.eq("disposition", disposition)
    return q.order("observed_at", desc=True).limit(max(1, min(limit, 500))).execute().data or []


def entity_summary(org_id: str, etype: str, eid: str) -> dict[str, Any] | None:
    state, version = load_profile(org_id, etype, eid)
    if not version:
        return None
    cfg = _settings(org_id)[1]
    meta = state["meta"]
    out: dict[str, Any] = {"entity": {"type": etype, "id": eid}, "mature": engine.is_mature(state, cfg),
                           "events": meta["events"], "active_days": len(set(meta["days"])),
                           "first_seen": _iso(meta["first"]) if meta["first"] else None,
                           "last_seen": _iso(meta["last"]) if meta["last"] else None, "peer_group": meta.get("peer"),
                           "requirements": {"min_events": cfg.min_events, "min_days": cfg.min_days}, "features": {}}
    for name, fs in state["f"].items():
        feat = FEATURES.get(name)
        if not feat:
            continue
        if feat.kind == "cat":
            out["features"][name] = model.cat_summary(fs, top=8)
        elif feat.kind == "hour":
            out["features"][name] = {"hour_histogram_utc": fs["h"], "observations": fs["n"], "active_days": len(fs["days"])}
        elif feat.kind in ("bucket", "breadth"):
            out["features"][name] = {"hours_of_history": len(fs["hist"])}
        elif feat.kind == "num":
            out["features"][name] = {"samples": len(fs["v"])}
    return out


def set_disposition(org_id: str, anomaly_id: str, disposition: str, user_id: str | None, note: str | None = None) -> dict[str, Any] | None:
    if disposition not in ("confirmed", "benign", "expected"):
        raise ValueError("disposition must be confirmed, benign or expected")
    client = get_supabase_admin()
    rows = client.table("behavior_anomalies").select("*").eq("organization_id", org_id).eq("id", anomaly_id).limit(1).execute().data
    if not rows:
        return None
    a = rows[0]
    client.table("behavior_anomalies").update({"disposition": disposition, "disposition_by": user_id, "disposition_at": _now_iso()}) \
        .eq("organization_id", org_id).eq("id", anomaly_id).execute()
    if disposition == "expected":
        teach(org_id, a)
        add_suppression(org_id, entity_type=a["entity_type"], entity_id=a["entity_id"], feature=a["feature"],
                        value_key=a["value_key"] or "*", reason=note or "marked expected by analyst", user_id=user_id)
    elif disposition == "benign":
        add_suppression(org_id, entity_type=a["entity_type"], entity_id=a["entity_id"], feature=a["feature"],
                        value_key=a["value_key"] or "*", reason=note or "marked benign by analyst", user_id=user_id,
                        expires_in_days=30)
    return {**a, "disposition": disposition}


def teach(org_id: str, anomaly: dict[str, Any]) -> None:
    """Analyst says this is normal: establish the value in the baseline immediately (the only way an anomalous value
    skips the candidate period)."""
    feat = FEATURES.get(anomaly["feature"])
    if not feat:
        return
    for _ in range(CAS_ATTEMPTS):
        state, version = load_profile(org_id, anomaly["entity_type"], anomaly["entity_id"])
        if not version:
            return
        fs = state["f"].setdefault(feat.name, {"cat": model.cat_new, "hour": model.hours_new, "num": model.num_new,
                                               "bucket": model.bucket_new, "breadth": model.breadth_new}[feat.kind]())
        ts = datetime.fromisoformat(str(anomaly["observed_at"]).replace("Z", "+00:00")).timestamp()
        if feat.kind == "cat":
            key = anomaly["value_key"]
            fs["cand"].pop(key, None)
            d = model.day_of(ts)
            fs["seen"][key] = [max(2, fs["seen"].get(key, [0])[0]), ts, ts, 2, d]
        elif feat.kind == "hour":
            h = int(anomaly["value_key"]) if str(anomaly["value_key"]).isdigit() else int(ts % 86400 // 3600)
            fs["h"][h] += max(5, fs["n"] // 10)
            fs["n"] = sum(fs["h"])
        elif feat.kind in ("num", "bucket", "breadth"):
            obs = (anomaly.get("explanation") or {}).get("observed")
            if isinstance(obs, (int, float)):
                if feat.kind == "num":
                    model.num_observe(fs, float(obs), learn=True)
                elif feat.kind == "bucket":
                    fs["hist"].append(round(__import__("math").log1p(float(obs)), 4))
                else:
                    fs["hist"].append(int(obs))
        if save_profile(org_id, anomaly["entity_type"], anomaly["entity_id"], state, version):
            return


def add_suppression(org_id: str, *, entity_type: str = "*", entity_id: str = "*", feature: str = "*", value_key: str = "*",
                    reason: str, user_id: str | None, expires_in_days: float | None = None) -> dict[str, Any]:
    row = {"organization_id": org_id, "entity_type": entity_type, "entity_id": entity_id, "feature": feature,
           "value_key": value_key or "*", "reason": reason[:500], "created_by": user_id,
           **({"expires_at": (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat()} if expires_in_days else {})}
    return (get_supabase_admin().table("behavior_suppressions").insert(row).execute().data or [row])[0]


def status(org_id: str) -> dict[str, Any]:
    client = get_supabase_admin()
    enabled, cfg = _settings(org_id)
    profiles = client.table("behavior_profiles").select("entity_type,event_count,state").eq("organization_id", org_id) \
        .in_("entity_type", ["user", "host"]).limit(5000).execute().data or []
    mature = {"user": 0, "host": 0}
    total = {"user": 0, "host": 0}
    for p in profiles:
        total[p["entity_type"]] += 1
        if engine.is_mature(p["state"] or engine.new_state(), cfg):
            mature[p["entity_type"]] += 1
    since = _iso(time.time() - 86400)
    recent = client.table("behavior_anomalies").select("alerted,disposition,suppressed_reason").eq("organization_id", org_id) \
        .gte("observed_at", since).limit(5000).execute().data or []
    disp = client.table("behavior_anomalies").select("disposition").eq("organization_id", org_id).neq("disposition", "open").limit(5000).execute().data or []
    confirmed = sum(1 for d in disp if d["disposition"] == "confirmed")
    benign = sum(1 for d in disp if d["disposition"] == "benign")
    return {
        "enabled": enabled, "sensitivity": get_settings_row(org_id).get("sensitivity", "balanced"),
        "profiles": total, "mature_profiles": mature,
        "learning": enabled and sum(mature.values()) == 0,
        "last_24h": {"anomalies": len(recent), "alerts": sum(1 for r in recent if r["alerted"]),
                     "suppressed": sum(1 for r in recent if r.get("suppressed_reason"))},
        "analyst_feedback": {"confirmed": confirmed, "benign": benign,
                             "precision": round(confirmed / (confirmed + benign), 3) if confirmed + benign else None},
        "maturity_requirements": {"min_events": cfg.min_events, "min_days": cfg.min_days},
    }


# ------------------------------------------------------------------------------------------ bootstrap from history
def learn_batch(org_id: str, events: list[dict[str, Any]]) -> dict[str, int]:
    """Learn from historical events (oldest first) without alerting or recording anomalies. Used to start with a
    baseline on day one instead of waiting weeks, and by the validation lab."""
    enabled, cfg = _settings(str(org_id))
    per_entity: dict[tuple[str, str], list[features.Obs]] = {}
    for ev in events:
        for o in features.extract(ev):
            per_entity.setdefault((o.etype, o.eid), []).append(o)
    learned = 0
    for (etype, eid), olist in per_entity.items():
        olist.sort(key=lambda o: o.ts)
        for _ in range(CAS_ATTEMPTS):
            state, version = load_profile(org_id, etype, eid)
            delta = engine.PopDelta()
            by_event: dict[float, list[features.Obs]] = {}
            for o in olist:
                by_event.setdefault(o.ts, []).append(o)
            for _ts, group in sorted(by_event.items()):
                res = engine.analyze(state, group, cfg, None, learn=True)
                delta.mature += res.delta.mature
                for k, n in res.delta.holders.items():
                    delta.holders[k] = delta.holders.get(k, 0) + n
            if save_profile(org_id, etype, eid, state, version):
                _apply_population(org_id, etype, state["meta"].get("peer"), delta)
                learned += len(olist)
                break
    return {"entities": len(per_entity), "observations": learned}


def backfill(org_id: str, days: int = 14, max_events: int = 20000) -> dict[str, Any]:
    client = get_supabase_admin()
    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    done, entities, offset = 0, 0, 0
    while done < max_events:
        page = (client.table("events").select("*").eq("organization_id", org_id).eq("alerted", False)
                .gte("observed_at", since).order("observed_at").range(offset, offset + 499).execute().data or [])
        if not page:
            break
        r = learn_batch(org_id, page)
        entities = max(entities, r["entities"])
        done += len(page)
        offset += len(page)
        if len(page) < 500:
            break
    return {"events": done, "entities_touched": entities}


# ------------------------------------------------------------------------------------------ peer groups
def recluster(org_id: str, threshold: float = 0.35) -> dict[str, Any]:
    """Group comparable entities (users by the systems/resources they use, hosts by the software/destinations they use)
    with single-pass leader clustering on Jaccard similarity. Groups of fewer than three are not statistically useful
    and are dropped. Rebuilds the population (peer prevalence) counters from the current baselines."""
    client = get_supabase_admin()
    cfg = _settings(org_id)[1]
    result: dict[str, Any] = {}
    for etype, feats in (("user", ("auth.host", "resource.access")), ("host", ("proc.name", "net.dest"))):
        rows = (client.table("behavior_profiles").select("entity_id,state,version").eq("organization_id", org_id)
                .eq("entity_type", etype).limit(5000).execute().data or [])
        members: dict[str, dict[str, Any]] = {}
        sets: dict[str, set[str]] = {}
        for r in rows:
            st = r["state"] or engine.new_state()
            if not engine.is_mature(st, cfg):
                continue
            members[r["entity_id"]] = {"state": st, "version": int(r["version"])}
            sets[r["entity_id"]] = {f"{f}:{k}" for f in feats for k in (st["f"].get(f, {}).get("seen", {}) or {})}
        leaders: list[tuple[str, set[str]]] = []
        assign: dict[str, str] = {}
        for eid in sorted(sets, key=lambda e: -len(sets[e])):
            s = sets[eid]
            best, best_j = None, 0.0
            for lid, ls in leaders:
                union = len(s | ls)
                j = len(s & ls) / union if union else 0.0
                if j > best_j:
                    best, best_j = lid, j
            if best is not None and best_j >= threshold:
                assign[eid] = assign[best]
            else:
                gid = f"g{len(leaders) + 1}"
                leaders.append((eid, s))
                assign[eid] = gid
                assign.setdefault(eid, gid)
        sizes: dict[str, int] = {}
        for g in assign.values():
            sizes[g] = sizes.get(g, 0) + 1
        keep = {g for g, n in sizes.items() if n >= 3}
        pops: dict[str, dict[str, Any]] = {etype: {"mature": 0, "holders": {}}}
        for g in keep:
            pops[f"{etype}:pg:{g}"] = {"mature": 0, "holders": {}}
        for eid, m in members.items():
            g = assign.get(eid)
            peer = g if g in keep else None
            st = m["state"]
            st["meta"]["peer"] = peer
            st["meta"]["counted"] = True
            for scope in ([etype] + ([f"{etype}:pg:{peer}"] if peer else [])):
                pops[scope]["mature"] += 1
                for f in feats + tuple(n for n, ft in FEATURES.items() if ft.entity == etype and ft.kind == "cat"):
                    for k in st["f"].get(f, {}).get("seen", {}) or {}:
                        b = pops[scope]["holders"].setdefault(f, {})
                        b[k] = b.get(k, 0) + 1
            if not save_profile(org_id, etype, eid, st, m["version"]):
                behavior_conflicts.inc()
        for scope, st in pops.items():
            rows2 = client.table("behavior_profiles").select("version").eq("organization_id", org_id) \
                .eq("entity_type", "population").eq("entity_id", scope).limit(1).execute().data
            body = {"state": st, "updated_at": _now_iso(), "last_seen": _now_iso()}
            if rows2:
                client.table("behavior_profiles").update({**body, "version": int(rows2[0]["version"]) + 1}) \
                    .eq("organization_id", org_id).eq("entity_type", "population").eq("entity_id", scope).execute()
            else:
                client.table("behavior_profiles").insert({"organization_id": org_id, "entity_type": "population", "entity_id": scope, "version": 1, **body}).execute()
        result[etype] = {"mature_entities": len(members), "groups": len(keep), "grouped": sum(sizes[g] for g in keep)}
    invalidate(org_id)
    return result
