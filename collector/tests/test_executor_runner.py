from tb_executor.blocker import DryRunBlocker
from tb_executor.config import ExecutorConfig
from tb_executor.runner import run


class FakeClient:
    def __init__(self, pending):
        self.pending = pending
        self.reports = []

    def list_pending_blocks(self):
        return self.pending

    def report(self, approval_id, result, detail=None):
        self.reports.append((approval_id, result, detail))
        return {}


def _cfg(**kw):
    base = dict(base_url="x", email="e", password="p")
    base.update(kw)
    return ExecutorConfig(**base)


def test_runner_blocks_public_ip_and_reports_executed():
    client = FakeClient([{"id": "a1", "target": "8.8.8.8"}])
    blocker = DryRunBlocker()
    run(_cfg(), client=client, blocker=blocker, iterations=1)
    assert blocker.blocked == ["8.8.8.8"]
    assert client.reports == [("a1", "executed", "[dry-run] would block 8.8.8.8")]


def test_runner_rejects_private_ip_by_default_and_reports_failed():
    client = FakeClient([{"id": "a2", "target": "10.0.0.5"}])
    run(_cfg(), client=client, blocker=DryRunBlocker(), iterations=1)
    assert client.reports[0][0] == "a2"
    assert client.reports[0][1] == "failed"


def test_runner_blocks_private_ip_when_allow_private():
    client = FakeClient([{"id": "a3", "target": "192.168.1.50"}])
    blocker = DryRunBlocker()
    run(_cfg(allow_private=True), client=client, blocker=blocker, iterations=1)
    assert blocker.blocked == ["192.168.1.50"]
    assert client.reports[0][1] == "executed"
