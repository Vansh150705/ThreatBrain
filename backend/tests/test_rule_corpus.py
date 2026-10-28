"""Every built-in rule ships inline positive and negative tests; this runs all of them."""
import pytest

from app.detection import attack_catalog
from app.detection.engine import load_rule_file, run_rule_tests

VERSION, RULES = load_rule_file()


def test_corpus_loads_and_is_versioned():
    assert VERSION not in ("", "0")
    assert len(RULES) >= 90
    assert len({r.id for r in RULES}) == len(RULES)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_has_positive_and_negative_tests(rule):
    expects = [bool(t.get("expect_match", t.get("match", True))) for t in rule.tests]
    assert True in expects, f"{rule.id} has no positive test"
    assert False in expects, f"{rule.id} has no negative test"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_inline_tests_pass(rule):
    failures = [r for r in run_rule_tests(rule) if not r["passed"]]
    assert not failures, failures


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_attack_mapping_is_valid(rule):
    assert rule.techniques, f"{rule.id} has no ATT&CK technique"
    assert not attack_catalog.validate_ids(list(rule.techniques))
    assert rule.tactics
