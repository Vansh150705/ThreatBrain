"""Behavioural analysis of one entity's observations against its baseline (pure; persistence lives in
``services/behavior_service``).

Decision flow per event
  1. each observation is compared with the entity's baseline BEFORE it is learned (so a value cannot vouch for itself);
  2. a deviation becomes an *anomaly* with a score, an explanation and a feature family;
  3. anomalies are kept as evidence, but only a *combination* alerts: a single weak deviation (a new hotel Wi-Fi) is
     recorded and never alerts; unrelated families of deviation inside the decay window add up (new network + unusual
     hour + new system); one extremely strong family (an order-of-magnitude outbound volume spike) can alert alone;
  4. events that already triggered a deterministic detection are NOT learned from, and anomalous values enter a baseline
     only through the candidate mechanism in ``model.cat_observe`` (repeated over days), never on first sight.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from app.behavior import model
from app.behavior.config import BehaviorConfig
from app.behavior.features import FEATURES, Feature, Obs

# features where an immature entity may still be flagged by comparison with peers alone (high-signal, rarely benign)
COLD_START_FEATURES = {"priv.action", "resource.access", "proc.exec_path"}
_STATE_KEYS = {"cat": model.cat_new, "hour": model.hours_new, "num": model.num_new,
               "bucket": model.bucket_new, "breadth": model.breadth_new}


def new_state() -> dict[str, Any]:
    return {"meta": {"events": 0, "first": 0, "last": 0, "days": [], "peer": None, "counted": False},
            "f": {}, "recent": [], "alerts": []}


RECENT_SECONDS = 7 * 86400


@dataclass
class PopulationView:
    """What fraction of comparable entities have a value: established in their baseline (``holders``) or merely seen
    recently (``recent``: [distinct entities, last seen]). The second term is what makes a fleet-wide rollout - a new
    package, a new CDN - stop looking suspicious on the second host."""
    mature: int = 0
    holders: dict[str, dict[str, int]] = field(default_factory=dict)
    scope: str = "tenant"
    recent: dict[str, dict[str, list[float]]] = field(default_factory=dict)

    def prevalence(self, feature: str, key: str, now: float = 0.0) -> float:
        if not self.mature:
            return 0.0
        est = self.holders.get(feature, {}).get(key, 0)
        rec = self.recent.get(feature, {}).get(key)
        seen = rec[0] if rec and (not now or now - rec[1] <= RECENT_SECONDS) else 0
        return max(est, seen) / self.mature


@dataclass
class Anomaly:
    etype: str
    eid: str
    feature: str
    family: str
    key: str
    score: float
    ts: float
    explanation: dict[str, Any]

    def public(self) -> dict[str, Any]:
        return {"feature": self.feature, "family": self.family, "key": self.key, "score": round(self.score, 3),
                "explanation": self.explanation}


@dataclass
class PopDelta:
    mature: int = 0
    holders: dict[tuple[str, str], int] = field(default_factory=dict)
    first_seen: dict[tuple[str, str], float] = field(default_factory=dict)   # (feature, key) -> ts of this entity's first sight


@dataclass
class Result:
    anomalies: list[Anomaly]
    delta: PopDelta
    mature: bool
    learning: bool


# ------------------------------------------------------------------------------------------ maturity
def is_mature(state: dict[str, Any], cfg: BehaviorConfig) -> bool:
    m = state["meta"]
    return m["events"] >= cfg.min_events and len(set(m["days"])) >= cfg.min_days


def _touch(state: dict[str, Any], ts: float) -> None:
    m = state["meta"]
    m["events"] += 1
    m["first"] = ts if not m["first"] else min(m["first"], ts)
    m["last"] = max(m["last"], ts)
    d = model.day_of(ts)
    if d not in m["days"]:
        m["days"] = sorted(set(m["days"] + [d]))[-90:]


def _feature_state(state: dict[str, Any], feat: Feature) -> dict[str, Any]:
    fs = state["f"]
    if feat.name not in fs:
        fs[feat.name] = _STATE_KEYS[feat.kind]()
    return fs[feat.name]


def _clamp(x: float, hi: float = 0.97) -> float:
    return max(0.0, min(hi, x))


def _peer_factor(pop: PopulationView | None, feature: str, key: str, cfg: BehaviorConfig, now: float = 0.0) -> tuple[float, dict[str, Any] | None]:
    if pop is None or pop.mature < cfg.peer_min_entities:
        return 1.0, None
    p = pop.prevalence(feature, key, now)
    factor = 1.0 - cfg.peer_discount * min(1.0, p / 0.25)
    return factor, {"scope": pop.scope, "prevalence": round(p, 3), "peers": pop.mature}


# ------------------------------------------------------------------------------------------ detectors
BURST_FEATURES = {"auth.host", "resource.access", "cloud.action"}
BURST_WINDOW = 3600
CHURN_LIMIT = 0.25


def _cat(state, feat: Feature, o: Obs, cfg, pop, mature, learn) -> tuple[Anomaly | None, str]:
    fs = _feature_state(state, feat)
    summary = model.cat_summary(fs)
    before = model.cat_status(fs, o.key)
    churn = (len(fs["seen"]) + len(fs["cand"])) / max(1, fs["total"])
    high_churn = fs["total"] >= 30 and churn > CHURN_LIMIT       # this entity constantly meets new values here (a browsing workstation)
    burst = 1
    if before == "novel" and mature:
        nov = fs.setdefault("nov", [])
        nov[:] = [t for t in nov if o.ts - t <= BURST_WINDOW][-40:]
        nov.append(o.ts)
        burst = len(nov)
    outcome = model.cat_observe(fs, o.key, o.ts, cfg, learn=learn)
    if before == "known" or outcome == "promoted":
        return None, outcome
    base = state["meta"]
    detail: dict[str, Any] = {"feature": feat.name, "method": "categorical-novelty", "observed": o.key, "status": before,
                              "baseline": {"events": base["events"], "active_days": len(set(base["days"])),
                                           "distinct_values": summary["distinct"], "observations": summary["observations"],
                                           "top": summary["top"]}}
    factor, peer = _peer_factor(pop, feat.name, o.key, cfg, o.ts)
    if peer:
        detail["peer"] = peer
    novelty = 1.0 if before == "novel" else 0.4
    ext = 1.0
    if feat.name == "net.dest":
        ext = 1.0 if o.meta.get("external") else 0.4
    elif feat.name == "auth.source_net":
        if o.meta.get("external"):
            had_external = any(not k.startswith(("10.", "192.168.", "172.")) for k in fs["seen"])
            ext = 1.0 if had_external else 1.1
            detail["external_source"] = True
        else:
            ext = 0.55      # another PRIVATE network (new VLAN, floor, VPN pool) is far weaker evidence than a first public one
    if not mature:
        # cold start: only a strong peer signal can flag an entity with no history of its own
        if feat.name in COLD_START_FEATURES and peer and peer["prevalence"] <= cfg.cold_start_peer_prevalence:
            score = _clamp(feat.weight * novelty * 0.5)
            detail.update(cold_start=True)
            detail["summary"] = f"{o.eid}: {_desc(feat, o)} — the account has little history yet, but only {peer['prevalence']:.0%} of {peer['peers']} comparable entities do this."
            return Anomaly(_etype(feat), o.eid, feat.name, feat.family, o.key, score, o.ts, {**detail, "score": round(score, 3)}), outcome
        return None, outcome
    if summary["observations"] < feat.min_obs:    # this entity barely uses this feature: nothing to deviate from
        return None, outcome
    if high_churn and burst < 6:
        return None, outcome
    score = feat.weight * novelty * factor * ext
    if feat.name in BURST_FEATURES and burst >= 3:
        # several never-seen values within the hour: a sweep (lateral movement, bulk access), not a one-off
        score += 0.1 * (burst - 2) * max(0.3, factor)
        detail["novel_values_last_hour"] = burst
    score = _clamp(score)
    detail["summary"] = (f"{o.eid}: {_desc(feat, o)} — never seen in {len(set(base['days']))} days of activity "
                         f"({summary['observations']} comparable observations)."
                         + (f" {peer['prevalence']:.0%} of {peer['peers']} peers do this." if peer else ""))
    if before == "candidate":
        detail["summary"] += " (seen before but not yet established)"
    return Anomaly(_etype(feat), o.eid, feat.name, feat.family, o.key, score, o.ts, {**detail, "score": round(score, 3), "weight": feat.weight}), outcome


def _etype(feat: Feature) -> str:
    return feat.entity


def _desc(feat: Feature, o: Obs) -> str:
    return {
        "auth.source_net": f"signed in from {o.key}", "auth.host": f"signed in to {o.key}",
        "priv.action": f"performed privileged action {o.key}", "cloud.action": f"called {o.key}",
        "resource.access": f"accessed {o.key}", "proc.name": f"ran '{o.key}'",
        "proc.pair": f"process relationship {o.key}", "proc.exec_path": f"ran '{o.key.split(':')[-1]}' from a user-writable location ({o.key.split(':')[0]})",
        "net.dest": f"connected to {o.key}", "net.port": f"connected on port {o.key}",
    }.get(feat.name, f"{feat.name}={o.key}")


def _hour(state, feat: Feature, o: Obs, cfg, mature, learn) -> Anomaly | None:
    fs = _feature_state(state, feat)
    hc = state["f"].setdefault("auth.hour.cand", model.cat_new())
    anomaly = None
    flagged = False
    if mature and fs["n"] >= cfg.min_auth_events_for_hour and len(fs["days"]) >= cfg.min_days + 2:
        p = model.hour_probability(fs, o.ts)
        if p < cfg.hour_prob_threshold:
            flagged = True
            factor = 0.5 + 0.5 * (1 - p / cfg.hour_prob_threshold)
            score = _clamp(feat.weight * factor)
            hr = int(o.ts % 86400 // 3600)
            top = sorted(range(24), key=lambda h: -fs["h"][h])[:3]
            anomaly = Anomaly("user", o.eid, feat.name, feat.family, o.key, score, o.ts, {
                "feature": feat.name, "method": "hour-of-day-histogram", "observed": f"{hr:02d}:00 UTC",
                "baseline": {"observations": fs["n"], "active_days": len(fs["days"]), "usual_hours_utc": sorted(top)},
                "probability": round(p, 4), "threshold": cfg.hour_prob_threshold, "score": round(score, 3), "weight": feat.weight,
                "summary": f"{o.eid} signed in at {hr:02d}:00 UTC; only {p:.1%} of this account's sign-ins happen around that hour."})
    if not learn:
        return anomaly
    if not flagged:
        model.hours_observe(fs, o.ts, learn=True)
    else:
        # an unusual hour is learned only if it recurs on several days (a changed schedule), never on first sight
        if model.cat_observe(hc, o.key, o.ts, cfg, learn=True) == "promoted":
            h = int(o.key)
            fs["h"][h] += max(8, fs["n"] // 10)     # recurred on several days: now an ordinary hour for this account
            fs["n"] = sum(fs["h"])
    return anomaly


def _num(state, feat: Feature, o: Obs, cfg, mature, learn) -> Anomaly | None:
    fs = _feature_state(state, feat)
    anomaly = None
    if mature and len(fs["v"]) >= cfg.min_numeric_samples and o.value >= cfg.bytes_flow_floor:
        z, med, mad = model.robust_z(fs, o.value)
        if z >= cfg.z_threshold and learn:
            known_peak = model.peak_known(fs, o.ts, o.value)
            model.peak_record(fs, o.ts, o.value)
            z = 0.0 if known_peak else z
        elif z >= cfg.z_threshold and model.peak_known(fs, o.ts, o.value):
            z = 0.0
        if z >= cfg.z_threshold:
            score = _clamp(_numeric_score(feat.weight, z, cfg.z_threshold))
            anomaly = Anomaly("host", o.eid, feat.name, feat.family, o.meta.get("dest", ""), score, o.ts, {
                "feature": feat.name, "method": "robust-z (median/MAD on log bytes)", "observed": int(o.value),
                "baseline": {"samples": len(fs["v"]), "median_bytes": int(math.expm1(med)),
                             "typical_range_bytes": [int(math.expm1(med - 2 * max(1.4826 * mad, 0.25))), int(math.expm1(med + 2 * max(1.4826 * mad, 0.25)))]},
                "z": round(z, 1), "threshold": cfg.z_threshold, "destination": o.meta.get("dest"), "score": round(score, 3), "weight": feat.weight,
                "summary": f"{o.eid} sent {_mb(o.value)} to {o.meta.get('dest')} in one transfer; this host's typical transfer is about {_mb(math.expm1(med))}."})
    model.num_observe(fs, o.value, learn=learn and anomaly is None)
    return anomaly


def _bucket(state, feat: Feature, o: Obs, cfg, mature, learn) -> Anomaly | None:
    fs = _feature_state(state, feat)
    total = model.bucket_add(fs, o.ts, o.value, learn=learn)
    if not (mature and len(fs["hist"]) >= 24 and total >= cfg.bytes_hour_floor):
        return None
    z, med, mad = model.bucket_z(fs, total)
    if z < cfg.z_threshold:
        return None
    if model.peak_known(fs, o.ts, total):
        if learn:
            model.peak_record(fs, o.ts, total)
        return None
    if learn and not fs["cur"][2]:
        model.peak_record(fs, o.ts, total)       # once per hour: a recurring peak is established after several distinct days
    score = _clamp(_numeric_score(feat.weight, z, cfg.z_threshold))
    if learn:
        model.bucket_flag(fs)
    return Anomaly("host", o.eid, feat.name, feat.family, "", score, o.ts, {
        "feature": feat.name, "method": "robust-z on hourly outbound totals (median/MAD on log bytes)", "observed": int(total),
        "baseline": {"hours_of_history": len(fs["hist"]), "median_bytes_per_hour": int(math.expm1(med))},
        "z": round(z, 1), "threshold": cfg.z_threshold, "score": round(score, 3), "weight": feat.weight,
        "summary": f"{o.eid} has sent {_mb(total)} outbound this hour; its typical hour is about {_mb(math.expm1(med))}."})


def _breadth(state, feat: Feature, o: Obs, cfg, mature, learn) -> Anomaly | None:
    fs = _feature_state(state, feat)
    count = model.breadth_add(fs, o.ts, o.key, learn=learn)
    if not (mature and len(fs["hist"]) >= 24 and count >= cfg.breadth_floor):
        return None
    z, med, mad = model.breadth_z(fs, count)
    if z < cfg.z_threshold:
        return None
    score = _clamp(_numeric_score(feat.weight, z, cfg.z_threshold))
    if learn:
        model.breadth_flag(fs)
    return Anomaly("user", o.eid, feat.name, feat.family, "", score, o.ts, {
        "feature": feat.name, "method": "robust-z on distinct systems per hour", "observed": count,
        "baseline": {"hours_of_history": len(fs["hist"]), "median_systems_per_hour": round(math.expm1(med), 1)},
        "z": round(z, 1), "threshold": cfg.z_threshold, "score": round(score, 3), "weight": feat.weight,
        "summary": f"{o.eid} reached {count} different systems this hour; a normal hour is about {math.expm1(med):.0f}."})


def _numeric_score(weight: float, z: float, threshold: float) -> float:
    """Half of the feature weight is earned by crossing the threshold; the rest grows with how extreme the deviation is."""
    return 0.5 * weight + 0.5 * (1 - math.exp(-(z - threshold + 1) / 3))


def _mb(n: float) -> str:
    return f"{n / 1_000_000:.1f} MB" if n >= 100_000 else f"{n / 1000:.1f} KB"


# ------------------------------------------------------------------------------------------ public API
def analyze(state: dict[str, Any], observations: list[Obs], cfg: BehaviorConfig, pop: PopulationView | None,
            *, learn: bool) -> Result:
    """Score ``observations`` (all for ONE entity) against ``state`` and, when ``learn``, update the state."""
    if not observations:
        return Result([], PopDelta(), is_mature(state, cfg), not is_mature(state, cfg))
    ts = observations[0].ts
    pname = state["f"].get("proc.name")
    new_procs = {o.key for o in observations if o.feature == "proc.name" and pname is not None and model.cat_status(pname, o.key) != "known"} \
        or {o.key for o in observations if o.feature == "proc.name" and pname is None}
    was_mature = is_mature(state, cfg)
    mature = was_mature
    anomalies: list[Anomaly] = []
    delta = PopDelta()
    for o in observations:
        feat = FEATURES[o.feature]
        a: Anomaly | None = None
        outcome = ""
        if feat.kind == "cat":
            a, outcome = _cat(state, feat, o, cfg, pop, mature, learn)
            if a and o.feature == "proc.pair" and o.key.split(">")[-1] in new_procs:
                a = None        # a brand-new program necessarily has a new parent/child pair: that is one signal, not two
        elif feat.kind == "hour":
            a = _hour(state, feat, o, cfg, mature, learn)
        elif feat.kind == "num":
            a = _num(state, feat, o, cfg, mature, learn)
        elif feat.kind == "bucket":
            a = _bucket(state, feat, o, cfg, mature, learn)
        elif feat.kind == "breadth":
            a = _breadth(state, feat, o, cfg, mature, learn)
        if a and a.score >= cfg.record_score:
            anomalies.append(a)
        if outcome == "promoted" and state["meta"]["counted"]:
            delta.holders[(o.feature, o.key)] = delta.holders.get((o.feature, o.key), 0) + 1
        if feat.kind == "cat" and learn and outcome == "novel":
            delta.first_seen[(o.feature, o.key)] = o.ts
    if learn:
        _touch(state, ts)
        if not state["meta"]["counted"] and is_mature(state, cfg):
            state["meta"]["counted"] = True
            delta.mature = 1
            for fname, fs in state["f"].items():
                if fname in FEATURES and FEATURES[fname].kind == "cat":
                    for k in fs["seen"]:
                        delta.holders[(fname, k)] = delta.holders.get((fname, k), 0) + 1
    return Result(anomalies, delta, is_mature(state, cfg), not is_mature(state, cfg))


def apply_delta(view: PopulationView, delta: PopDelta) -> None:
    """Fold one entity's population change into an in-memory view (used by the validation lab; the service does the
    same against its stored counters)."""
    view.mature += delta.mature
    for (f, k), n in delta.holders.items():
        view.holders.setdefault(f, {})[k] = view.holders.get(f, {}).get(k, 0) + n
    for (f, k), ts in delta.first_seen.items():
        rec = view.recent.setdefault(f, {}).setdefault(k, [0, 0.0])
        rec[0] += 1
        rec[1] = max(rec[1], ts)


REALERT_SECONDS = 7 * 86400


# ------------------------------------------------------------------------------------------ combination
@dataclass
class Decision:
    alert: bool
    risk: float
    families: dict[str, float]
    reason: str
    contributing: list[Anomaly]


def decide(state: dict[str, Any], current: list[Anomaly], cfg: BehaviorConfig, now: float) -> Decision:
    """Combine this event's anomalies with the entity's recent evidence (time-decayed), one signal per family.

    A value that already produced an alert is not allowed to alert again for a week (a traveller on a new network is
    one case, not one per sign-in); it stays in the evidence so it can still corroborate something genuinely new."""
    akeys = state.setdefault("akeys", {})
    for k in [k for k, t in akeys.items() if now - t > 2 * REALERT_SECONDS]:
        akeys.pop(k, None)
    fresh_ids = {id(a) for a in current if now - akeys.get(f"{a.feature}|{a.key}", -1e12) > REALERT_SECONDS}
    horizon = now - 48 * 3600
    state["recent"] = [r for r in state["recent"] if r[0] >= horizon][-40:]
    best: dict[tuple[str, str], float] = {}          # strongest decayed evidence per (family, feature)
    for ts, family, score, feature, _k in state["recent"]:
        age_h = max(0.0, (now - ts) / 3600)
        best[(family, feature)] = max(best.get((family, feature), 0.0), score * 0.5 ** (age_h / cfg.half_life_hours))
    for a in current:
        best[(a.family, a.feature)] = max(best.get((a.family, a.feature), 0.0), a.score)
    # a family is ONE signal, but two different features inside it (new network AND new system) corroborate each other
    fam: dict[str, float] = {}
    for (family, _feature), sc in best.items():
        fam[family] = 1 - (1 - fam.get(family, 0.0)) * (1 - sc)
    fam = {f: min(0.95, v) for f, v in fam.items()}
    cur_fams = {a.family for a in current if id(a) in fresh_ids}
    live = {f: s for f, s in fam.items() if s >= cfg.record_score}
    risk = 1 - math.prod(1 - s for s in live.values()) if live else 0.0
    top_cur = max((fam[f] for f in cur_fams), default=0.0)
    if not cur_fams:
        return Decision(False, risk, live, "", [])
    contributing = [a for a in current if id(a) in fresh_ids]
    if top_cur >= cfg.single_family_score:
        return Decision(True, risk, live, "single strong signal", contributing)
    if len(live) >= cfg.min_families and risk >= cfg.alert_score:
        return Decision(True, risk, live, f"{len(live)} independent signals within {cfg.half_life_hours:g}h half-life", contributing)
    return Decision(False, risk, live, "below combined threshold", [])


def mark_alerted(state: dict[str, Any], anomalies: list[Anomaly], now: float) -> None:
    akeys = state.setdefault("akeys", {})
    for a in anomalies:
        akeys[f"{a.feature}|{a.key}"] = now
    if len(akeys) > 200:
        for k in sorted(akeys, key=akeys.get)[: len(akeys) - 200]:
            akeys.pop(k, None)


def remember(state: dict[str, Any], anomalies: list[Anomaly]) -> None:
    for a in anomalies:
        state["recent"].append([a.ts, a.family, round(a.score, 3), a.feature, a.key])
    state["recent"] = state["recent"][-40:]
