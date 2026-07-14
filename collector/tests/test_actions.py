from tb_executor.actions import ActionDispatcher
from tb_executor.user_control import is_disableable_user


def _disp(**kw):
    base = dict(enabled_actions=("block_ip", "disable_user"), dry_run=True)
    base.update(kw)
    return ActionDispatcher(**base)


def test_block_public_ip_executed():
    result, _ = _disp().handle("block_ip", "8.8.8.8")
    assert result == "executed"


def test_block_private_ip_refused():
    result, detail = _disp(allow_private=False).handle("block_ip", "10.0.0.5")
    assert result == "failed" and "guard refused" in detail


def test_disable_normal_user_executed():
    result, _ = _disp().handle("disable_user", "eviluser")
    assert result == "executed"


def test_disable_protected_user_refused():
    result, detail = _disp().handle("disable_user", "root")
    assert result == "failed" and "protected" in detail


def test_block_range_executed():
    result, _ = _disp(enabled_actions=("block_ip", "block_range")).handle("block_range", "8.8.8.0/24")
    assert result == "executed"


def test_block_range_too_broad_refused():
    d = _disp(enabled_actions=("block_range",), allow_private=True)
    result, detail = d.handle("block_range", "10.0.0.0/8")
    assert result == "failed" and "broad" in detail


def test_action_not_enabled_refused():
    d = ActionDispatcher(enabled_actions=("block_ip",), dry_run=True)
    result, detail = d.handle("disable_user", "bob")
    assert result == "failed" and "not enabled" in detail


def test_user_guard_basics():
    assert is_disableable_user("bob")[0] is True
    assert is_disableable_user("root")[0] is False
    assert is_disableable_user("")[0] is False
