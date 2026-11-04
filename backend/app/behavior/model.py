"""Pure, bounded statistical state for behavioural baselines (no I/O).

Every structure is a plain JSON-serialisable dict so it can be stored as JSONB, and every structure is bounded in size so
neither a noisy entity nor an attacker generating endless distinct values can grow a baseline without limit.

Methods (chosen for the detection need, not for novelty):
  * Categorical novelty   - "has this account ever used this network/host/process before?" is a set-membership question;
                            a probabilistic model adds nothing and loses explainability.
  * Hour-of-day profile   - a Laplace-smoothed histogram; the rarity of an hour is its smoothed probability.
  * Robust numeric z      - median / MAD on log-volumes. Byte counts are heavy-tailed, so mean/stddev would let one past
                            burst hide the next; median/MAD are not moved by occasional spikes.
  * Hourly volume buckets - totals per clock hour compared with the entity's own history of hourly totals.
"""

from __future__ import annotations

import math
import statistics
from typing import Any

from app.behavior.config import BehaviorConfig

DAY = 86_400
HOUR = 3_600
MAX_RING = 256


def day_of(ts: float) -> int:
    return int(ts // DAY)


# --------------------------------------------------------------------------------------- categorical
def cat_new() -> dict[str, Any]:
    return {"seen": {}, "cand": {}, "total": 0, "grow": [0, 0]}


def cat_status(state: dict[str, Any], key: str) -> str:
    """known = established in the baseline; candidate = seen before but not yet trusted; novel = never seen."""
    if key in state["seen"]:
        return "known"
    return "candidate" if key in state["cand"] else "novel"


def cat_observe(state: dict[str, Any], key: str, ts: float, cfg: BehaviorConfig, *, learn: bool) -> str:
    """Record one observation and return the status the key had BEFORE it. Returns 'promoted' when this observation
    moved a candidate into the baseline."""
    before = cat_status(state, key)
    if not learn:
        return before
    state["total"] += 1
    d = day_of(ts)
    seen = state["seen"]
    if key in seen:
        row = seen[key]          # [count, first_ts, last_ts, n_days, last_day]
        row[0] += 1
        row[2] = max(row[2], ts)
        row[1] = min(row[1], ts)
        if d != row[4]:
            row[3] += 1
            row[4] = d
        return "known"
    cand = state["cand"]
    row = cand.get(key)
    if row is None:               # [count, first_ts, n_days, last_day]
        if len(cand) >= cfg.max_keys_per_feature:
            oldest = min(cand, key=lambda k: cand[k][1])
            cand.pop(oldest)
        cand[key] = [1, ts, 1, d]
        return before
    row[0] += 1
    row[1] = min(row[1], ts)
    if d != row[3]:
        row[2] += 1
        row[3] = d
    span_h = (ts - row[1]) / HOUR
    if row[2] >= cfg.promote_days or (row[0] >= cfg.promote_count and span_h >= cfg.promote_span_hours):
        grow_day, grow_n = state["grow"]
        if grow_day != d:
            state["grow"] = [d, 0]
            grow_n = 0
        if grow_n < cfg.daily_new_keys_cap:
            cand.pop(key)
            seen[key] = [row[0], row[1], ts, row[2], d]
            state["grow"][1] += 1
            if len(seen) > cfg.max_keys_per_feature:       # evict the least-used, oldest value
                victim = min(seen, key=lambda k: (seen[k][0], seen[k][2]))
                seen.pop(victim)
            return "promoted"
    return before


def cat_summary(state: dict[str, Any], top: int = 5) -> dict[str, Any]:
    seen = state["seen"]
    ranked = sorted(seen.items(), key=lambda kv: -kv[1][0])[:top]
    return {"distinct": len(seen), "observations": state["total"], "candidates": len(state["cand"]),
            "top": [[k, v[0]] for k, v in ranked]}


# --------------------------------------------------------------------------------------- hour of day
def hours_new() -> dict[str, Any]:
    return {"h": [0] * 24, "n": 0, "days": []}


def hours_observe(state: dict[str, Any], ts: float, *, learn: bool) -> None:
    if not learn:
        return
    h = int(ts % DAY // HOUR)
    state["h"][h] += 1
    state["n"] += 1
    if state["n"] > 5000:                       # exponential forgetting keeps the profile adaptive
        state["h"] = [c // 2 for c in state["h"]]
        state["n"] = sum(state["h"])
    d = day_of(ts)
    if not state["days"] or state["days"][-1] != d:
        state["days"] = (state["days"] + [d])[-60:]


def hour_probability(state: dict[str, Any], ts: float) -> float:
    h = int(ts % DAY // HOUR)
    # adjacent hours are 'near' normal: a login 20 minutes after the usual window is not a deviation
    near = state["h"][h] + 0.5 * (state["h"][(h - 1) % 24] + state["h"][(h + 1) % 24])
    return (near + 0.5) / (state["n"] + 12.0)


# --------------------------------------------------------------------------------------- numeric
def num_new() -> dict[str, Any]:
    return {"v": [], "n": 0}


def num_observe(state: dict[str, Any], value: float, *, learn: bool) -> None:
    if not learn:
        return
    state["n"] += 1
    state["v"].append(round(math.log1p(max(value, 0.0)), 4))
    if len(state["v"]) > MAX_RING:
        del state["v"][: len(state["v"]) - MAX_RING]


def robust_z(state: dict[str, Any], value: float) -> tuple[float, float, float]:
    """(z, median, mad) of log1p(value) against the stored ring. MAD is floored so a perfectly constant history does
    not turn every tiny change into an infinite z."""
    vals = state["v"]
    med = statistics.median(vals)
    mad = statistics.median([abs(v - med) for v in vals])
    scale = max(1.4826 * mad, 0.25)
    return (math.log1p(max(value, 0.0)) - med) / scale, med, mad


# --------------------------------------------------------------------------------------- hourly buckets
def bucket_new() -> dict[str, Any]:
    return {"cur": [0, 0.0, 0], "hist": [], "n": 0}


def _finish(state: dict[str, Any], cur_hour: int, total: float, bad: int) -> None:
    if cur_hour and not bad:      # an hour that produced an alert never becomes 'normal history'
        state["hist"].append(round(math.log1p(total), 4))
        state["n"] += 1
        if len(state["hist"]) > 168:
            del state["hist"][: len(state["hist"]) - 168]


def bucket_add(state: dict[str, Any], ts: float, amount: float, *, learn: bool) -> float:
    """Add to the clock-hour bucket containing ts; return the bucket total AFTER the addition (what the detector tests).
    When not learning (the event already triggered a deterministic detection) nothing is stored."""
    hour = int(ts // HOUR)
    cur_hour, total, bad = state["cur"]
    same = hour == cur_hour
    if not learn:
        return total + amount if same else amount
    if same:
        total += amount
        state["cur"] = [cur_hour, total, bad]
        return total
    if hour > cur_hour:
        _finish(state, cur_hour, total, bad)
        state["cur"] = [hour, amount, 0]
        return amount
    return amount          # a late event for a past hour: judged on its own, not merged into the current bucket


def bucket_flag(state: dict[str, Any]) -> None:
    state["cur"][2] = 1


def bucket_z(state: dict[str, Any], total: float) -> tuple[float, float, float]:
    return robust_z({"v": state["hist"]}, total)


# --------------------------------------------------------------------------------------- set-per-hour (breadth)
def breadth_new() -> dict[str, Any]:
    return {"cur": [0, [], 0], "hist": [], "n": 0}


def breadth_add(state: dict[str, Any], ts: float, member: str, *, learn: bool) -> int:
    hour = int(ts // HOUR)
    cur_hour, members, bad = state["cur"]
    same = hour == cur_hour
    if not learn:
        return len(set(members) | {member}) if same else 1
    if same:
        if member not in members and len(members) < 500:
            members.append(member)
        return len(members)
    if hour > cur_hour:
        if cur_hour and not bad:
            state["hist"].append(len(members))
            state["n"] += 1
            if len(state["hist"]) > 168:
                del state["hist"][: len(state["hist"]) - 168]
        state["cur"] = [hour, [member], 0]
        return 1
    return 1


def breadth_flag(state: dict[str, Any]) -> None:
    state["cur"][2] = 1


def breadth_z(state: dict[str, Any], count: int) -> tuple[float, float, float]:
    vals = [math.log1p(c) for c in state["hist"]]
    return robust_z({"v": vals}, count)


# --------------------------------------------------------------------------------------- recurring peaks
# A nightly backup is "unusual" relative to a typical hour but perfectly regular. Robust statistics ignore a minority of
# large values by design, so a recurring peak has to be remembered separately: when the same hour-of-day produces a flagged
# value on several different days, that hour's peak is established and values up to ~3x it stop being anomalies.
PEAK_DAYS = 3
PEAK_HEADROOM = 1.1        # natural-log headroom (~3x) above the established peak


def peak_known(fs: dict[str, Any], ts: float, value: float) -> bool:
    h = int(ts % DAY // HOUR)
    lv = math.log1p(max(value, 0.0))
    for hh in ((h - 1) % 24, h, (h + 1) % 24):
        p = fs.get("peaks", {}).get(str(hh))
        if p and p[0] >= PEAK_DAYS and lv <= p[1] + PEAK_HEADROOM:
            return True
    return False


def peak_record(fs: dict[str, Any], ts: float, value: float) -> None:
    """Remember a flagged value; establish a peak once it recurs on PEAK_DAYS distinct days within +-1 hour-of-day."""
    h, d = int(ts % DAY // HOUR), day_of(ts)
    ex = fs.setdefault("ex", [])
    ex.append([d, h, round(math.log1p(max(value, 0.0)), 3)])
    del ex[:-40]
    near = [e for e in ex if min((e[1] - h) % 24, (h - e[1]) % 24) <= 1]
    if len({e[0] for e in near}) >= PEAK_DAYS:
        fs.setdefault("peaks", {})[str(h)] = [len({e[0] for e in near}), max(e[2] for e in near)]
