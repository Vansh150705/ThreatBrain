import pytest

from app.detection.engine import RuleEngine, RuleError, rule_from_dict
from app.detection.sigma import convert

SIGMA_MIMIKATZ = """
title: Suspicious Mimikatz Command Line
id: 1
level: critical
tags: [attack.credential_access, attack.t1003.001]
falsepositives: [Penetration testing]
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    Image|endswith: '\\mimikatz.exe'
  selection_cli:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
  filter:
    User: 'TESTLAB\\pentester'
  condition: (selection_img or selection_cli) and not filter
"""


def _engine(rule):
    return RuleEngine([rule_from_dict(rule, source="sigma")])


def test_conversion_and_semantics():
    out = convert(SIGMA_MIMIKATZ)
    rule = out["rule"]
    assert rule["severity"] == "critical" and rule["techniques"] == ["T1003.001"] and rule["origin"] == "sigma"
    eng = _engine({**rule, "id": rule["rule_key"]})
    assert eng.evaluate({"command_line": "mimikatz.exe sekurlsa::logonpasswords", "raw_data": {}})
    assert eng.evaluate({"process_name": "mimikatz.exe", "raw_data": {}})
    assert not eng.evaluate({"command_line": "notepad.exe", "raw_data": {}})
    assert not eng.evaluate({"process_name": "mimikatz.exe", "username": "TESTLAB\\pentester", "raw_data": {}})  # filter works
    assert any("logsource" in w for w in out["warnings"])


def test_all_modifier_and_of_selection():
    out = convert("""
title: Both flags
level: medium
detection:
  sel1:
    CommandLine|contains|all: ['-nop', '-w hidden']
  sel2:
    CommandLine|contains: 'bypass'
  condition: 1 of sel*
""")
    eng = _engine({**out["rule"], "id": "sigma-both-flags"})
    assert eng.evaluate({"command_line": "powershell -nop -w hidden", "raw_data": {}})
    assert not eng.evaluate({"command_line": "powershell -nop", "raw_data": {}})
    assert eng.evaluate({"command_line": "powershell -ep bypass", "raw_data": {}})


@pytest.mark.parametrize("bad,msg", [
    ("title: x agg\ndetection:\n  s: {CommandLine|contains: a}\n  condition: s | count() > 5\n", "aggregation"),
    ("title: x time\ndetection:\n  s: {CommandLine|contains: a}\n  timeframe: 5m\n  condition: s\n", "timeframe"),
    ("title: x b64\ndetection:\n  s: {CommandLine|base64offset|contains: a}\n  condition: s\n", "modifier"),
    ("title: x ref\ndetection:\n  s: {CommandLine|contains: a}\n  condition: s and nothere\n", "unknown selection"),
    ("title: nodet\n", "detection"),
    ("not: [valid", "YAML"),
])
def test_unsupported_input_is_rejected_loudly(bad, msg):
    with pytest.raises(RuleError, match=msg):
        convert(bad)


def test_converted_regex_cannot_be_unbounded():
    out = convert("title: wild\nlevel: low\ndetection:\n  s: {CommandLine: 'a*b'}\n  condition: s\n")
    assert ".*" not in str(out["rule"]["match"])
    rule_from_dict({**out["rule"], "id": "sigma-wild"}, source="sigma")  # passes the ReDoS guard
