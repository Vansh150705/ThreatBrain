import pytest

from app.detection.correlation import load_correlations, run_inline_tests
from app.detection.engine import get_engine

CORS = load_correlations()
RULE_IDS = {r.id for r in get_engine().rules}


def test_correlations_load():
    assert len(CORS) >= 12 and len({c.id for c in CORS}) == len(CORS)


@pytest.mark.parametrize("c", CORS, ids=lambda c: c.id)
def test_inline_scenarios(c):
    results = run_inline_tests(c)
    assert any(r["expected"] for r in results) and any(not r["expected"] for r in results)
    assert all(r["passed"] for r in results), results


@pytest.mark.parametrize("c", CORS, ids=lambda c: c.id)
def test_references_only_real_rules(c):
    selectors = list(c.stages) + ([c.select] if c.select else [])
    for sel in selectors:
        for rid in sel.get("rules", []):
            assert rid in RULE_IDS, f"{c.id} references unknown rule {rid}"
