from tb_executor.client import ExecutorClient


class FakeResp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeHttp:
    def __init__(self):
        self.calls = []
        self.login_responses = []
        self.get_responses = []
        self.post_responses = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append(("POST", url, json, headers))
        if url.endswith("/auth/login"):
            return self.login_responses.pop(0)
        return self.post_responses.pop(0)

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(("GET", url, params, headers))
        return self.get_responses.pop(0)


def test_list_pending_actions_logs_in_and_returns_items():
    http = FakeHttp()
    http.login_responses = [FakeResp(200, {"access_token": "tok"})]
    http.get_responses = [FakeResp(200, {"items": [{"id": "a1", "action_type": "block_ip", "target": "203.0.113.42"}]})]
    c = ExecutorClient("http://x/api/v1", "e@x.co", "pw", http=http)
    items = c.list_pending_actions()
    assert items == [{"id": "a1", "action_type": "block_ip", "target": "203.0.113.42"}]
    assert http.calls[0][1].endswith("/auth/login")
    assert http.calls[1][3]["Authorization"] == "Bearer tok"


def test_report_posts_execution():
    http = FakeHttp()
    http.login_responses = [FakeResp(200, {"access_token": "tok"})]
    http.post_responses = [FakeResp(200, {"execution_status": "executed"})]
    c = ExecutorClient("http://x/api/v1", "e@x.co", "pw", http=http)
    out = c.report("a1", "executed", "iptables DROP added")
    assert out["execution_status"] == "executed"
    method, url, body, headers = http.calls[-1]
    assert url.endswith("/playbooks/approvals/a1/execution")
    assert body == {"result": "executed", "detail": "iptables DROP added"}
