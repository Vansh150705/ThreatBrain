from tb_executor.actions import ActionDispatcher
from tb_executor.config import ExecutorConfig
from tb_executor.runner import run


class FakeClient:
    def __init__(self, pending):
        self.pending = pending
        self.reports = []

    def list_pending_actions(self):
        return self.pending

    def report(self, approval_id, result, detail=None):
        self.reports.append((approval_id, result, detail))
        return {}


def _cfg(**kw):
    base = dict(base_url="x", email="e", password="p")
    base.update(kw)
    return ExecutorConfig(**base)


def _dispatcher(**kw):
    base = dict(enabled_actions=("block_ip", "disable_user"), dry_run=True)
    base.update(kw)
    return ActionDispatcher(**base)


def test_runner_blocks_public_ip_and_reports_executed():
    client = FakeClient([{"id": "a1", "action_type": "block_ip", "target": "8.8.8.8"}])
    run(_cfg(), client=client, dispatcher=_dispatcher(), iterations=1)
    assert client.reports == [("a1", "executed", "[dry-run] would block 8.8.8.8")]


def test_runner_rejects_private_ip_by_default():
    client = FakeClient([{"id": "a2", "action_type": "block_ip", "target": "10.0.0.5"}])
    run(_cfg(), client=client, dispatcher=_dispatcher(allow_private=False), iterations=1)
    assert client.reports[0][1] == "failed"


def test_runner_disables_user():
    client = FakeClient([{"id": "a3", "action_type": "disable_user", "target": "eviluser"}])
    run(_cfg(), client=client, dispatcher=_dispatcher(), iterations=1)
    assert client.reports[0][1] == "executed"


def test_runner_refuses_disable_when_action_not_enabled():
    client = FakeClient([{"id": "a4", "action_type": "disable_user", "target": "eviluser"}])
    run(_cfg(), client=client, dispatcher=_dispatcher(enabled_actions=("block_ip",)), iterations=1)
    assert client.reports[0][1] == "failed"
