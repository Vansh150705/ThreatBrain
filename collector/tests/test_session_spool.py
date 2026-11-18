import json
import threading
import time

import pytest

from tb_collector.config import Config, load_config
from tb_collector.emitter import Emitter, EmitterError
from tb_collector.runner import _tail, run
from tb_collector.spool import Spool
from tb_common.session import ApiSession, AuthError, TransientError
from tb_executor.actions import ActionDispatcher
from tb_executor.blocker import IptablesBlocker
from tb_executor.config import ExecutorConfig, load_executor_config
from tb_executor.runner import run as run_executor
from tb_executor.user_control import is_disableable_user


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body if body is not None else {}

    def json(self):
        return self._body


class ScriptedHttp:
    """Plays back a list of responses (or exceptions) for each method."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self, method, url, **kw):
        self.calls.append((method, url, kw))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def post(self, url, **kw):
        return self._next("post", url, **kw)

    def get(self, url, **kw):
        return self._next("get", url, **kw)


def session(http, **kw):
    return ApiSession("http://x/api/v1", api_key="tbk_key", http=http, sleep=lambda s: None, **kw)


# --------------------------------------------------------------- session ----
def test_api_key_header_is_sent_and_no_login_happens():
    http = ScriptedHttp(Resp(200, {"ok": 1}))
    assert session(http).json("post", "/ingest/event", json={}) == {"ok": 1}
    assert http.calls[0][2]["headers"]["X-API-Key"] == "tbk_key"
    assert "Authorization" not in http.calls[0][2]["headers"]
    assert len(http.calls) == 1


def test_retries_network_errors_and_5xx_then_succeeds():
    http = ScriptedHttp(ConnectionError("down"), Resp(503), Resp(200, {"ok": True}))
    assert session(http).json("get", "/x") == {"ok": True}
    assert len(http.calls) == 3


def test_gives_up_with_transient_error_after_max_attempts():
    http = ScriptedHttp(Resp(500), Resp(502), Resp(503))
    with pytest.raises(TransientError):
        session(http).json("get", "/x")


def test_rate_limit_429_is_retried():
    http = ScriptedHttp(Resp(429), Resp(200, {"ok": 1}))
    assert session(http).json("get", "/x") == {"ok": 1}


def test_rejected_api_key_is_not_retried():
    http = ScriptedHttp(Resp(401, {"detail": {"message": "revoked"}}))
    with pytest.raises(AuthError):
        session(http).json("get", "/x")
    assert len(http.calls) == 1


def test_wrong_scope_403_raises_auth_error_with_reason():
    http = ScriptedHttp(Resp(403, {"detail": {"message": "This API key is not allowed to call this endpoint."}}))
    with pytest.raises(AuthError, match="not allowed"):
        session(http).json("get", "/x")


def test_client_error_is_not_retried():
    http = ScriptedHttp(Resp(422, {"detail": "bad"}))
    with pytest.raises(Exception, match="422"):
        session(http).json("post", "/x", json={})
    assert len(http.calls) == 1


def test_requires_some_credentials():
    with pytest.raises(ValueError):
        ApiSession("http://x", http=object())


# --------------------------------------------------------------- emitter ----
def test_emitter_uses_async_flag_and_accepts_202():
    http = ScriptedHttp(Resp(202, {"run_id": "r1", "status": "queued"}))
    em = Emitter("http://x/api/v1", api_key="tbk_k", http=http, async_ingest=True)
    assert em.post_event({"event": {}})["run_id"] == "r1"
    assert http.calls[0][1].endswith("/ingest/event?async=true")


def test_emitter_marks_outages_transient_and_rejections_permanent():
    em = Emitter("http://x", api_key="tbk_k", http=ScriptedHttp(Resp(500), Resp(500), Resp(500)))
    em.session._sleep = lambda s: None
    with pytest.raises(EmitterError) as e:
        em.post_event({})
    assert e.value.transient is True
    em2 = Emitter("http://x", api_key="tbk_k", http=ScriptedHttp(Resp(422, {"detail": "bad"})))
    with pytest.raises(EmitterError) as e2:
        em2.post_event({})
    assert e2.value.transient is False


# ----------------------------------------------------------------- spool ----
def test_spool_is_durable_ordered_and_stops_on_first_failure(tmp_path):
    sp = Spool(str(tmp_path / "s.jsonl"))
    for i in range(4):
        sp.append({"n": i})
    assert len(Spool(str(tmp_path / "s.jsonl"))) == 4  # survives a restart
    sent = []

    def send(p):
        if p["n"] == 2:
            raise RuntimeError("still down")
        sent.append(p["n"])

    assert sp.replay(send) == 2 and sent == [0, 1]
    assert [i["n"] for i in sp._read()] == [2, 3]
    assert sp.replay(lambda p: sent.append(p["n"])) == 2
    assert len(sp) == 0 and sent == [0, 1, 2, 3]


def test_spool_is_bounded_and_private(tmp_path):
    path = tmp_path / "s.jsonl"
    sp = Spool(str(path), max_items=3)
    for i in range(5):
        sp.append({"n": i})
    assert [i["n"] for i in sp._read()] == [2, 3, 4], "oldest items are dropped first"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_spool_skips_corrupt_lines(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text('{"n": 1}\nnot json\n{"n": 2}\n')
    assert [i["n"] for i in Spool(str(path))._read()] == [1, 2]


# -------------------------------------------------------- tailing/runner ----
def test_tail_follows_appends_and_survives_rotation(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("old line\n")
    got, started = [], threading.Event()

    def consume():
        started.set()
        for line in _tail(str(log), poll=0.02):
            got.append(line.strip())
            if line.strip() == "ok":
                return

    t = threading.Thread(target=consume, daemon=True)
    t.start()
    started.wait()
    time.sleep(0.15)
    with open(log, "a") as fh:
        fh.write("first\n")
    time.sleep(0.2)
    log.rename(tmp_path / "auth.log.1")           # logrotate: move away...
    log.write_text("after-rotate\n")              # ...and recreate
    time.sleep(0.3)
    log.write_text("ok\n")                        # copytruncate: file shrinks below our offset
    t.join(timeout=3)
    assert got == ["first", "after-rotate", "ok"], got


class FlakyHttp:
    def __init__(self):
        self.up = False
        self.received = []

    def post(self, url, json=None, headers=None, timeout=None):
        if not self.up:
            raise ConnectionError("backend down")
        self.received.append(json)
        return Resp(202, {"run_id": "r"})


def test_runner_spools_when_backend_is_down_then_replays(tmp_path):
    log = tmp_path / "auth.log"
    lines = "".join(f"Oct 27 10:00:{i:02d} h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n" for i in range(12))
    log.write_text(lines)
    cfg = Config(base_url="http://x", collector_id="c", api_key="tbk_k", log_path=str(log),
                 threshold=5, spool_path=str(tmp_path / "spool.jsonl"))
    http = FlakyHttp()
    spool = Spool(cfg.spool_path)

    # follow=False reads from the start? _tail seeks to end, so feed via a one-shot engine call instead
    from tb_collector.engine import DetectionEngine, default_detectors
    from tb_collector.emitter import Emitter
    from tb_collector.normalizer import detection_to_ingest_payload

    engine = DetectionEngine(default_detectors(threshold=5))
    detections = [d for ln in lines.splitlines() for d in engine.process_line(ln, now=time.time())]
    assert detections, "fixture should trigger a brute-force detection"
    em = Emitter("http://x", api_key="tbk_k", http=http)
    em.session._sleep = lambda s: None
    for d in detections:
        payload = detection_to_ingest_payload(d, collector_id="c")
        try:
            em.post_event(payload)
        except EmitterError as exc:
            assert exc.transient
            spool.append(payload)
    assert len(spool) == len(detections) and http.received == []
    http.up = True
    assert spool.replay(em.post_event) == len(detections)
    assert len(http.received) == len(detections) and len(spool) == 0


# ---------------------------------------------------------------- config ----
def test_config_accepts_api_key_and_rejects_missing_credentials(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("base_url: http://x\napi_key: tbk_abc\ncollector_id: c\nlog_path: /var/log/auth.log\n")
    c = load_config(str(p))
    assert c.api_key == "tbk_abc" and c.email is None and c.async_ingest is True
    p.write_text("base_url: http://x\ncollector_id: c\nlog_path: /var/log/auth.log\n")
    with pytest.raises(ValueError, match="api_key"):
        load_config(str(p))


def test_executor_config_credentials(tmp_path):
    p = tmp_path / "e.yaml"
    p.write_text("base_url: http://x\napi_key: tbk_abc\n")
    assert load_executor_config(str(p)).api_key == "tbk_abc"
    p.write_text("base_url: http://x\nemail: a@b.c\n")
    with pytest.raises(ValueError):
        load_executor_config(str(p))


# -------------------------------------------------------------- executor ----
class FlakyClient:
    def __init__(self, items):
        self.items, self.reports, self.fail_reports = items, [], True

    def list_pending_actions(self):
        return self.items

    def report(self, i, result, detail=None):
        if self.fail_reports:
            raise RuntimeError("backend unreachable")
        self.reports.append((i, result))


def test_executor_survives_report_failures():
    client = FlakyClient([{"id": "a1", "action_type": "block_ip", "target": "8.8.4.4"}])
    cfg = ExecutorConfig(base_url="x", api_key="k")
    disp = ActionDispatcher(enabled_actions=("block_ip",), dry_run=True)
    run_executor(cfg, client=client, dispatcher=disp, iterations=2)  # must not raise
    client.fail_reports = False
    run_executor(cfg, client=client, dispatcher=disp, iterations=1)
    assert client.reports == [("a1", "executed")]


def test_ipv6_sources_use_ip6tables():
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode = rc

    def runner(args):
        calls.append(args)
        return R(1 if "-C" in args else 0)

    b = IptablesBlocker(runner=runner)
    assert "ip6tables" in b.block("2001:db8::bad")
    assert calls[-1][0] == "ip6tables"
    assert "iptables DROP" in b.block("203.0.113.9") and calls[-1][0] == "iptables"


@pytest.mark.parametrize("name", ["-h", "--help", "-o", "-L", "", " "])
def test_usernames_that_look_like_options_are_refused(name):
    ok, _ = is_disableable_user(name)
    assert ok is False


def test_usermod_gets_double_dash_separator():
    from tb_executor.user_control import LinuxUserDisabler

    seen = []

    class R:
        returncode = 0

    LinuxUserDisabler(runner=lambda a: (seen.append(a), R())[1]).disable("mallory")
    assert seen == [["usermod", "-L", "--", "mallory"]]
