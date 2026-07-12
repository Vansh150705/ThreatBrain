from tb_executor.blocker import DryRunBlocker


def test_dry_run_records_and_reports():
    b = DryRunBlocker()
    msg = b.block("203.0.113.42")
    assert "203.0.113.42" in msg
    assert b.blocked == ["203.0.113.42"]
