"""Tunable parameters of the behavioural layer, with validated per-tenant overrides.

Everything an analyst may want to change lives here; each value has hard bounds so a mistaken or hostile settings
update cannot disable the safety properties (cold-start gating, corroboration, alert budget).
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import Any


@dataclass(frozen=True)
class BehaviorConfig:
    # --- maturity: an entity must have this much history before its own baseline is trusted
    min_events: int = 40
    min_days: int = 3
    min_auth_events_for_hour: int = 50      # hour-of-day needs more samples than set membership
    min_numeric_samples: int = 30
    # --- learning (anti-poisoning)
    promote_days: int = 2                   # a new value joins the baseline after being seen on this many distinct days...
    promote_count: int = 5                  # ...or this many times spread over at least promote_span_hours
    promote_span_hours: float = 6.0
    daily_new_keys_cap: int = 20            # an entity can add at most this many baseline values per feature per day
    max_keys_per_feature: int = 400
    # --- scoring thresholds
    alert_score: float = 0.70               # combined (noisy-or over feature families) score needed to alert
    single_family_score: float = 0.85       # one family alone must reach this to alert without corroboration
    min_families: int = 2                   # distinct feature families needed for a combined alert
    record_score: float = 0.20              # anomalies below this are not even stored
    half_life_hours: float = 6.0            # anomaly evidence decays; unrelated oddities hours apart do not add up
    hour_prob_threshold: float = 0.02       # smoothed probability of an hour-of-day below which a login is unusual
    z_threshold: float = 4.0                # robust z (median/MAD) for numeric features
    bytes_hour_floor: int = 20_000_000      # never alert on an hourly outbound total below this, however unusual
    bytes_flow_floor: int = 5_000_000
    breadth_floor: int = 6                  # distinct hosts reached in an hour below which breadth is never unusual
    # --- peer comparison
    peer_discount: float = 0.8              # how strongly peer prevalence reduces a novelty score (0 = ignore peers)
    peer_min_entities: int = 8              # peers below this count are not statistically meaningful
    cold_start_peer_prevalence: float = 0.02
    # --- alert budget
    budget_per_entity_day: int = 3
    budget_per_org_hour: int = 30
    cooldown_hours: float = 24.0

    def sensitivity(self, level: str) -> "BehaviorConfig":
        if level == "low":
            return replace(self, alert_score=0.80, single_family_score=0.92, z_threshold=5.0, hour_prob_threshold=0.01)
        if level == "high":
            return replace(self, alert_score=0.60, single_family_score=0.78, z_threshold=3.2, hour_prob_threshold=0.04)
        return self


# name -> (min, max); anything not listed here cannot be overridden through the API
BOUNDS: dict[str, tuple[float, float]] = {
    "min_events": (20, 5000), "min_days": (2, 60), "min_auth_events_for_hour": (20, 5000), "min_numeric_samples": (15, 1000),
    "promote_days": (2, 14), "promote_count": (3, 100), "promote_span_hours": (1, 168),
    "daily_new_keys_cap": (1, 200), "alert_score": (0.5, 0.99), "single_family_score": (0.7, 1.0),
    "min_families": (2, 5), "half_life_hours": (1, 72), "hour_prob_threshold": (0.001, 0.1), "z_threshold": (2.5, 12),
    "bytes_hour_floor": (1_000_000, 10_000_000_000), "bytes_flow_floor": (500_000, 10_000_000_000),
    "breadth_floor": (3, 200), "peer_discount": (0.0, 0.95), "peer_min_entities": (3, 200),
    "budget_per_entity_day": (1, 50), "budget_per_org_hour": (1, 1000), "cooldown_hours": (1, 168),
}
_INT = {f.name for f in fields(BehaviorConfig) if f.type in ("int", int)}


class ConfigError(ValueError):
    pass


def validate_params(params: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if key not in BOUNDS:
            raise ConfigError(f"unknown or non-tunable parameter {key!r}")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{key} must be a number")
        lo, hi = BOUNDS[key]
        if not lo <= value <= hi:
            raise ConfigError(f"{key} must be between {lo} and {hi}")
        out[key] = int(value) if key in _INT else float(value)
    return out


def build(sensitivity: str = "balanced", params: dict[str, Any] | None = None) -> BehaviorConfig:
    cfg = BehaviorConfig().sensitivity(sensitivity)
    clean = validate_params(params or {})
    return replace(cfg, **clean) if clean else cfg
