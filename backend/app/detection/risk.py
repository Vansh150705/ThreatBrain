"""Transparent risk scoring (0-100) so analysts can see why something ranks high."""

from __future__ import annotations

from typing import Any

SEVERITY_WEIGHT = {"info": 5, "low": 25, "medium": 50, "high": 75, "critical": 95}
CRITICALITY_MULTIPLIER = {"low": 0.85, "medium": 1.0, "high": 1.15, "crown_jewel": 1.3}


def compute_risk_score(
    *,
    severity: str,
    confidence: int,
    asset_criticality: str | None = None,
    intel_score: int | None = None,
    rule_hit_count: int = 0,
) -> tuple[int, dict[str, Any]]:
    """Return (score, breakdown).

    base = severity weight x confidence; then scaled by asset criticality, nudged
    by external threat-intel score and the number of independent rule hits.
    """
    base = SEVERITY_WEIGHT.get(severity, 25) * (max(0, min(100, confidence)) / 100)
    mult = CRITICALITY_MULTIPLIER.get((asset_criticality or "").lower(), 1.0)
    intel_bonus = 0.0
    if intel_score is not None:
        intel_bonus = (max(0, min(100, intel_score)) - 50) / 50 * 8  # -8 .. +8
    corroboration = min(rule_hit_count, 3) * 2.0
    score = int(round(max(0.0, min(100.0, base * mult + intel_bonus + corroboration))))
    return score, {
        "base": round(base, 1),
        "asset_multiplier": mult,
        "intel_adjustment": round(intel_bonus, 1),
        "corroboration_bonus": corroboration,
    }
