from tb_collector.emitter import Emitter


class FakeResp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeHttp:
    """Scripts a sequence of responses per URL suffix."""

    def __init__(self):
        self.calls = []
        self.login_responses = []
        self.event_responses = []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append((url, json, headers))
        if url.endswith("/auth/login"):
            return self.login_responses.pop(0)
        if url.endswith("/ingest/event"):
            return self.event_responses.pop(0)
        raise AssertionError(f"unexpected url {url}")


def test_logs_in_then_posts_event():
    http = FakeHttp()
    http.login_responses = [FakeResp(200, {"access_token": "tok1"})]
    http.event_responses = [FakeResp(200, {"summary": {"stages_succeeded": 3}})]
    em = Emitter("http://x/api/v1", "e@x.co", "pw", http=http)
    out = em.post_event({"event": {"title": "t"}})
    assert out["summary"]["stages_succeeded"] == 3
    # first call is login, second carries the bearer token
    assert http.calls[0][0].endswith("/auth/login")
    assert http.calls[1][2]["Authorization"] == "Bearer tok1"


def test_reauths_on_401_then_succeeds():
    http = FakeHttp()
    http.login_responses = [FakeResp(200, {"access_token": "new"})]
    http.event_responses = [FakeResp(401, {"error": "expired"}), FakeResp(200, {"summary": {}})]
    em = Emitter("http://x/api/v1", "e@x.co", "pw", http=http)
    em._token = "old"  # pretend we already had a (now-stale) token
    out = em.post_event({"event": {"title": "t"}})
    assert out == {"summary": {}}
    # the retried event call used the refreshed token
    assert http.calls[-1][2]["Authorization"] == "Bearer new"
