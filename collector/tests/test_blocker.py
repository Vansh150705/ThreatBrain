from tb_executor.blocker import (
    DryRunBlocker,
    IptablesBlocker,
    WindowsFirewallBlocker,
    select_blocker,
)


class _Result:
    def __init__(self, rc):
        self.returncode = rc


def test_dry_run_records_and_reports():
    b = DryRunBlocker()
    msg = b.block("203.0.113.42")
    assert "203.0.113.42" in msg
    assert b.blocked == ["203.0.113.42"]


def test_windows_blocker_adds_rule_when_missing():
    calls = []

    def fake(args):
        calls.append(args)
        # first call = "show rule" -> not found (rc=1); second = "add rule" -> ok (rc=0)
        return _Result(1) if "show" in args else _Result(0)

    b = WindowsFirewallBlocker(runner=fake)
    msg = b.block("203.0.113.42")
    assert "Windows Firewall" in msg
    assert any("add" in c for c in calls)
    assert any("remoteip=203.0.113.42" in c for c in calls)


def test_windows_blocker_idempotent_when_rule_exists():
    def fake(args):
        return _Result(0)  # show rule -> found

    b = WindowsFirewallBlocker(runner=fake)
    assert "already blocked" in b.block("203.0.113.42")


def test_iptables_blocker_adds_rule_when_missing():
    def fake(args):
        return _Result(1) if "-C" in args else _Result(0)

    b = IptablesBlocker(runner=fake)
    assert "iptables DROP" in b.block("203.0.113.42")


def test_select_blocker_dry_run():
    assert isinstance(select_blocker(dry_run=True), DryRunBlocker)


def test_select_blocker_auto_by_platform():
    assert isinstance(select_blocker(dry_run=False, firewall="auto", system="Windows"), WindowsFirewallBlocker)
    assert isinstance(select_blocker(dry_run=False, firewall="auto", system="Linux"), IptablesBlocker)


def test_select_blocker_explicit():
    assert isinstance(select_blocker(dry_run=False, firewall="windows", system="Linux"), WindowsFirewallBlocker)
    assert isinstance(select_blocker(dry_run=False, firewall="iptables", system="Windows"), IptablesBlocker)
