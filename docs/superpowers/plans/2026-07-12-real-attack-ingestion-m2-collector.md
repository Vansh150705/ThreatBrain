# Real Attack Ingestion — Phase 2 (tb-collector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build `tb-collector`, a standalone daemon that tails a log file, detects SSH brute-force, and posts a normalized event to the backend's `/api/v1/ingest/event`. It is the flagship reusable collector — any host that writes logs can run it.

**Architecture:** A line-oriented, pluggable source-adapter design. The runner tails a file and feeds each line to adapters; an adapter returns a `Detection` when a threshold trips; a normalizer turns that into the ingest payload; an emitter authenticates and POSTs it. Pure detection/normalize logic is unit-tested (TDD); the emitter is tested against a fake HTTP poster; the runner is verified with a live local run.

**Tech Stack:** Python 3.11, `requests`, `PyYAML`, `tenacity`; `pytest` for tests. Standalone package under `collector/` with its own venv — does **not** touch the backend or its requirements.

## Global Constraints

- New code lives under `collector/`. Do **not** modify `backend/` in this phase.
- Commit style: Conventional Commits. **Never** add a Claude co-author; commits are authored by the repo owner only.
- The event payload MUST match the backend `IngestEventRequest` contract exactly: `{ event: TriageInput, source_system?: str, collector_id?: str }`, where `TriageInput` requires a non-empty `title`.
- The adapter interface is line-oriented and clock-injectable so detection logic is deterministic under test: `process_line(line: str, *, now: float) -> Detection | None`.

---

### Task 1: Package scaffold + `Detection` model + test harness

**Files:**
- Create: `collector/tb_collector/__init__.py`, `collector/tb_collector/models.py`
- Create: `collector/requirements.txt`, `collector/requirements-dev.txt`, `collector/pytest.ini`, `collector/README.md`
- Test: `collector/tests/__init__.py`, `collector/tests/test_models.py`

**Interfaces:**
- Produces: `Detection` dataclass with fields `kind: str, source_ip: str, username: str | None, count: int, window_seconds: int, first_seen: datetime, last_seen: datetime, sample_lines: list[str]`.

- [ ] **Step 1: Create requirements files**

`collector/requirements.txt`:
```
requests==2.32.3
PyYAML==6.0.2
tenacity==9.0.0
```

`collector/requirements-dev.txt`:
```
-r requirements.txt
pytest==8.3.4
```

`collector/pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
```

- [ ] **Step 2: Write the `Detection` model**

`collector/tb_collector/models.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Detection:
    """One aggregated security detection ready to be normalized and sent."""

    kind: str
    source_ip: str
    username: str | None
    count: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    sample_lines: list[str] = field(default_factory=list)
```

`collector/tb_collector/__init__.py`:
```python
from tb_collector.models import Detection

__all__ = ["Detection"]
```

- [ ] **Step 3: Write the failing test**

`collector/tests/test_models.py`:
```python
from datetime import datetime, timezone

from tb_collector.models import Detection


def test_detection_holds_fields():
    now = datetime(2026, 7, 12, tzinfo=timezone.utc)
    d = Detection(
        kind="ssh_bruteforce",
        source_ip="203.0.113.42",
        username="root",
        count=12,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
    )
    assert d.source_ip == "203.0.113.42"
    assert d.count == 12
    assert d.sample_lines == []
```

- [ ] **Step 4: Create the venv and install dev deps**

```bash
cd collector
python -m venv venv
./venv/Scripts/python.exe -m pip install -r requirements-dev.txt
```

- [ ] **Step 5: Run the test (expect PASS)**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest -q
```
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add collector/
git commit -m "feat(collector): scaffold tb-collector package and Detection model"
```

---

### Task 2: SSH brute-force adapter (parser + sliding window + cooldown) — TDD

**Files:**
- Create: `collector/tb_collector/adapters/__init__.py`, `collector/tb_collector/adapters/base.py`, `collector/tb_collector/adapters/ssh_bruteforce.py`
- Test: `collector/tests/test_ssh_bruteforce.py`

**Interfaces:**
- Consumes: `Detection` from `tb_collector.models`.
- Produces:
  - `SourceAdapter` ABC with `process_line(self, line: str, *, now: float) -> Detection | None`.
  - `AuthLogSSHBruteForce(threshold: int = 10, window_seconds: int = 60, cooldown_seconds: int = 300, kind: str = "ssh_bruteforce")`.

- [ ] **Step 1: Write the failing tests**

`collector/tests/test_ssh_bruteforce.py`:
```python
from tb_collector.adapters.ssh_bruteforce import AuthLogSSHBruteForce

FAIL = "May 26 14:01:02 kali sshd[1234]: Failed password for root from 203.0.113.42 port 55214 ssh2"
FAIL_INVALID = "May 26 14:01:03 kali sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 55215 ssh2"
OTHER = "May 26 14:01:04 kali sshd[1234]: Accepted password for jane from 10.0.0.5 port 500 ssh2"


def test_below_threshold_no_detection():
    a = AuthLogSSHBruteForce(threshold=5, window_seconds=60)
    for i in range(4):
        assert a.process_line(FAIL, now=float(i)) is None


def test_threshold_trips_once_and_reports_ip_and_user():
    a = AuthLogSSHBruteForce(threshold=5, window_seconds=60)
    out = None
    for i in range(5):
        out = a.process_line(FAIL, now=float(i))
    assert out is not None
    assert out.source_ip == "203.0.113.42"
    assert out.username == "root"
    assert out.count == 5


def test_invalid_user_line_is_parsed():
    a = AuthLogSSHBruteForce(threshold=1, window_seconds=60)
    out = a.process_line(FAIL_INVALID, now=0.0)
    assert out is not None
    assert out.username == "admin"


def test_non_failure_lines_ignored():
    a = AuthLogSSHBruteForce(threshold=1, window_seconds=60)
    assert a.process_line(OTHER, now=0.0) is None
    assert a.process_line("garbage", now=1.0) is None


def test_cooldown_suppresses_repeat_detections():
    a = AuthLogSSHBruteForce(threshold=3, window_seconds=60, cooldown_seconds=300)
    first = None
    for i in range(3):
        first = a.process_line(FAIL, now=float(i))
    assert first is not None
    # more failures during cooldown -> no new detection
    assert a.process_line(FAIL, now=10.0) is None
    assert a.process_line(FAIL, now=20.0) is None
    # after cooldown, a fresh burst detects again
    later = 0
    out = None
    for j in range(3):
        out = a.process_line(FAIL, now=400.0 + j)
    assert out is not None


def test_window_evicts_old_attempts():
    a = AuthLogSSHBruteForce(threshold=3, window_seconds=60)
    assert a.process_line(FAIL, now=0.0) is None
    assert a.process_line(FAIL, now=1.0) is None
    # third attempt is outside the 60s window from the first two but only 2 in window
    assert a.process_line(FAIL, now=120.0) is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest tests/test_ssh_bruteforce.py -q
```
Expected: FAIL / import error (module not created yet).

- [ ] **Step 3: Write the adapter base**

`collector/tb_collector/adapters/__init__.py`:
```python
```
(empty)

`collector/tb_collector/adapters/base.py`:
```python
from __future__ import annotations

from abc import ABC, abstractmethod

from tb_collector.models import Detection


class SourceAdapter(ABC):
    """Turns raw log lines into aggregated Detections."""

    @abstractmethod
    def process_line(self, line: str, *, now: float) -> Detection | None:
        """Feed one log line; return a Detection when a threshold trips, else None."""
```

- [ ] **Step 4: Write the SSH brute-force adapter**

`collector/tb_collector/adapters/ssh_bruteforce.py`:
```python
from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timezone

from tb_collector.adapters.base import SourceAdapter
from tb_collector.models import Detection

# Matches: "Failed password for [invalid user ]<user> from <ip> port ..."
_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


class AuthLogSSHBruteForce(SourceAdapter):
    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
        kind: str = "ssh_bruteforce",
    ) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.kind = kind
        self._events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._cooldown_until: dict[str, float] = {}

    def process_line(self, line: str, *, now: float) -> Detection | None:
        m = _FAILED_RE.search(line)
        if not m:
            return None
        ip = m.group("ip")
        user = m.group("user")

        if now < self._cooldown_until.get(ip, 0.0):
            return None

        window = self._events[ip]
        window.append((now, user))
        cutoff = now - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

        if len(window) >= self.threshold:
            first_ts = window[0][0]
            self._cooldown_until[ip] = now + self.cooldown_seconds
            detection = Detection(
                kind=self.kind,
                source_ip=ip,
                username=user,
                count=len(window),
                window_seconds=self.window_seconds,
                first_seen=datetime.fromtimestamp(first_ts, tz=timezone.utc),
                last_seen=datetime.fromtimestamp(now, tz=timezone.utc),
                sample_lines=[line.strip()],
            )
            window.clear()
            return detection
        return None
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest tests/test_ssh_bruteforce.py -q
```
Expected: all passed.

- [ ] **Step 6: Commit**

```bash
git add collector/tb_collector/adapters/ collector/tests/test_ssh_bruteforce.py
git commit -m "feat(collector): add SSH brute-force auth.log adapter with window and cooldown"
```

---

### Task 3: Normalizer (`Detection` → ingest payload) — TDD

**Files:**
- Create: `collector/tb_collector/normalizer.py`
- Test: `collector/tests/test_normalizer.py`

**Interfaces:**
- Consumes: `Detection`.
- Produces: `detection_to_ingest_payload(d: Detection, *, collector_id: str, asset_name: str | None = None) -> dict` returning `{source_system, collector_id, event}` where `event` matches `TriageInput`.

- [ ] **Step 1: Write the failing test**

`collector/tests/test_normalizer.py`:
```python
from datetime import datetime, timezone

from tb_collector.models import Detection
from tb_collector.normalizer import detection_to_ingest_payload


def _sample() -> Detection:
    now = datetime(2026, 7, 12, 9, 0, 0, tzinfo=timezone.utc)
    return Detection(
        kind="ssh_bruteforce",
        source_ip="203.0.113.42",
        username="root",
        count=12,
        window_seconds=60,
        first_seen=now,
        last_seen=now,
        sample_lines=["Failed password for root from 203.0.113.42"],
    )


def test_payload_shape_and_required_title():
    p = detection_to_ingest_payload(_sample(), collector_id="kali-01", asset_name="kali-box")
    assert p["source_system"] == "tb-collector/ssh_bruteforce"
    assert p["collector_id"] == "kali-01"
    ev = p["event"]
    assert ev["title"] and isinstance(ev["title"], str)
    assert ev["source_ip"] == "203.0.113.42"
    assert ev["username"] == "root"
    assert ev["event_type"] == "authentication.brute_force"
    assert ev["asset_name"] == "kali-box"
    assert ev["raw_data"]["failed_count"] == 12
    assert ev["raw_data"]["window_seconds"] == 60


def test_asset_name_optional():
    p = detection_to_ingest_payload(_sample(), collector_id="kali-01")
    assert p["event"]["asset_name"] is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest tests/test_normalizer.py -q
```
Expected: FAIL (module not created).

- [ ] **Step 3: Write the normalizer**

`collector/tb_collector/normalizer.py`:
```python
from __future__ import annotations

from typing import Any

from tb_collector.models import Detection


def detection_to_ingest_payload(
    d: Detection,
    *,
    collector_id: str,
    asset_name: str | None = None,
) -> dict[str, Any]:
    """Turn a Detection into the backend /ingest/event request body."""
    user = d.username or "unknown"
    return {
        "source_system": f"tb-collector/{d.kind}",
        "collector_id": collector_id,
        "event": {
            "title": f"SSH brute-force from {d.source_ip}",
            "description": (
                f"{d.count} failed SSH logins for user '{user}' "
                f"within {d.window_seconds}s."
            ),
            "source": "authentication",
            "event_type": "authentication.brute_force",
            "source_ip": d.source_ip,
            "username": d.username,
            "asset_name": asset_name,
            "raw_data": {
                "failed_count": d.count,
                "window_seconds": d.window_seconds,
                "first_seen": d.first_seen.isoformat(),
                "last_seen": d.last_seen.isoformat(),
                "sample_lines": d.sample_lines[:5],
            },
        },
    }
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest -q
```
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add collector/tb_collector/normalizer.py collector/tests/test_normalizer.py
git commit -m "feat(collector): add Detection-to-ingest-payload normalizer"
```

---

### Task 4: Config loader — TDD

**Files:**
- Create: `collector/tb_collector/config.py`, `collector/collector.example.yaml`
- Test: `collector/tests/test_config.py`

**Interfaces:**
- Produces: `Config` dataclass `{ base_url, email, password, collector_id, asset_name, threshold, window_seconds, cooldown_seconds, log_path }` and `load_config(path: str) -> Config`.

- [ ] **Step 1: Write the failing test**

`collector/tests/test_config.py`:
```python
from tb_collector.config import load_config


def test_load_config(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "base_url: http://localhost:8000/api/v1\n"
        "email: test@acme.example\n"
        "password: secret\n"
        "collector_id: kali-01\n"
        "asset_name: kali-box\n"
        "log_path: /var/log/auth.log\n"
        "threshold: 8\n"
        "window_seconds: 45\n"
        "cooldown_seconds: 200\n"
    )
    c = load_config(str(p))
    assert c.base_url == "http://localhost:8000/api/v1"
    assert c.email == "test@acme.example"
    assert c.collector_id == "kali-01"
    assert c.threshold == 8
    assert c.window_seconds == 45


def test_defaults_applied(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "base_url: http://localhost:8000/api/v1\n"
        "email: a@b.c\n"
        "password: x\n"
        "collector_id: k\n"
        "log_path: /var/log/auth.log\n"
    )
    c = load_config(str(p))
    assert c.threshold == 10
    assert c.window_seconds == 60
    assert c.cooldown_seconds == 300
    assert c.asset_name is None
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest tests/test_config.py -q
```
Expected: FAIL.

- [ ] **Step 3: Write the config loader**

`collector/tb_collector/config.py`:
```python
from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass
class Config:
    base_url: str
    email: str
    password: str
    collector_id: str
    log_path: str
    asset_name: str | None = None
    threshold: int = 10
    window_seconds: int = 60
    cooldown_seconds: int = 300


def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return Config(
        base_url=data["base_url"],
        email=data["email"],
        password=data["password"],
        collector_id=data["collector_id"],
        log_path=data["log_path"],
        asset_name=data.get("asset_name"),
        threshold=int(data.get("threshold", 10)),
        window_seconds=int(data.get("window_seconds", 60)),
        cooldown_seconds=int(data.get("cooldown_seconds", 300)),
    )
```

`collector/collector.example.yaml`:
```yaml
# Copy to collector.yaml and fill in. chmod 600 collector.yaml.
base_url: https://vansh150705-threatbrain-backend.hf.space/api/v1
email: you@example.com
password: your-threatbrain-password
collector_id: kali-lab-01
asset_name: kali-box
log_path: /var/log/auth.log
threshold: 10
window_seconds: 60
cooldown_seconds: 300
```

- [ ] **Step 4: Run to verify it passes**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest -q
```
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add collector/tb_collector/config.py collector/collector.example.yaml collector/tests/test_config.py
git commit -m "feat(collector): add YAML config loader"
```

---

### Task 5: Emitter (auth + POST with re-login) — TDD with a fake poster

**Files:**
- Create: `collector/tb_collector/emitter.py`
- Test: `collector/tests/test_emitter.py`

**Interfaces:**
- Produces: `Emitter(base_url, email, password, http=None)` with `post_event(payload: dict) -> dict`. Uses an injected `http` object exposing `.post(url, json=..., headers=...)` and returning an object with `.status_code` and `.json()`. On 401 it re-logs-in once and retries.

- [ ] **Step 1: Write the failing tests**

`collector/tests/test_emitter.py`:
```python
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
    http.login_responses = [FakeResp(200, {"access_token": "old"}), FakeResp(200, {"access_token": "new"})]
    http.event_responses = [FakeResp(401, {"error": "expired"}), FakeResp(200, {"summary": {}})]
    em = Emitter("http://x/api/v1", "e@x.co", "pw", http=http)
    em._token = "old"  # pretend we already had a token
    out = em.post_event({"event": {"title": "t"}})
    assert out == {"summary": {}}
    # the retried event call used the refreshed token
    assert http.calls[-1][2]["Authorization"] == "Bearer new"
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest tests/test_emitter.py -q
```
Expected: FAIL.

- [ ] **Step 3: Write the emitter**

`collector/tb_collector/emitter.py`:
```python
from __future__ import annotations

from typing import Any


class EmitterError(Exception):
    pass


class Emitter:
    def __init__(self, base_url: str, email: str, password: str, http: Any = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.password = password
        if http is None:
            import requests

            http = requests.Session()
        self.http = http
        self._token: str | None = None

    def _login(self) -> None:
        resp = self.http.post(
            f"{self.base_url}/auth/login",
            json={"email": self.email, "password": self.password},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code != 200:
            raise EmitterError(f"login failed: {resp.status_code}")
        self._token = resp.json()["access_token"]

    def post_event(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._token is None:
            self._login()

        resp = self._post_event(payload)
        if resp.status_code == 401:
            # token expired mid-run; re-login once and retry
            self._login()
            resp = self._post_event(payload)

        if resp.status_code != 200:
            raise EmitterError(f"ingest failed: {resp.status_code} {resp.json()}")
        return resp.json()

    def _post_event(self, payload: dict[str, Any]):
        return self.http.post(
            f"{self.base_url}/ingest/event",
            json=payload,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            timeout=180,
        )
```

- [ ] **Step 4: Run to verify they pass**

```bash
cd collector && ./venv/Scripts/python.exe -m pytest -q
```
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add collector/tb_collector/emitter.py collector/tests/test_emitter.py
git commit -m "feat(collector): add authenticating emitter with 401 re-login"
```

---

### Task 6: Runner + CLI + systemd unit + live local smoke test

**Files:**
- Create: `collector/tb_collector/runner.py`, `collector/tb_collector/__main__.py`, `collector/systemd/tb-collector.service`
- Update: `collector/README.md`

**Interfaces:**
- Consumes: `Config`, `AuthLogSSHBruteForce`, `detection_to_ingest_payload`, `Emitter`.
- Produces: `run(config: Config, *, http=None, follow=True) -> None` that tails `config.log_path`, feeds lines to the adapter, and emits detections. `python -m tb_collector --config collector.yaml`.

- [ ] **Step 1: Write the runner**

`collector/tb_collector/runner.py`:
```python
from __future__ import annotations

import time

from tb_collector.adapters.ssh_bruteforce import AuthLogSSHBruteForce
from tb_collector.config import Config
from tb_collector.emitter import Emitter
from tb_collector.normalizer import detection_to_ingest_payload


def _tail(path: str, *, follow: bool = True):
    """Yield new lines appended to a file (like tail -f)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)  # start at end
        while True:
            line = fh.readline()
            if line:
                yield line
            elif follow:
                time.sleep(0.5)
            else:
                return


def run(config: Config, *, http=None, follow: bool = True) -> None:
    adapter = AuthLogSSHBruteForce(
        threshold=config.threshold,
        window_seconds=config.window_seconds,
        cooldown_seconds=config.cooldown_seconds,
    )
    emitter = Emitter(config.base_url, config.email, config.password, http=http)

    print(f"[tb-collector] watching {config.log_path} (threshold={config.threshold}/{config.window_seconds}s)")
    for line in _tail(config.log_path, follow=follow):
        detection = adapter.process_line(line, now=time.time())
        if detection is None:
            continue
        payload = detection_to_ingest_payload(
            detection, collector_id=config.collector_id, asset_name=config.asset_name
        )
        print(f"[tb-collector] DETECTED brute-force from {detection.source_ip} "
              f"({detection.count} fails) -> posting")
        try:
            result = emitter.post_event(payload)
            summary = result.get("summary", {})
            print(f"[tb-collector] posted OK: {summary}")
        except Exception as exc:  # keep running through transient failures
            print(f"[tb-collector] post failed: {exc}")
```

- [ ] **Step 2: Write the CLI entrypoint**

`collector/tb_collector/__main__.py`:
```python
from __future__ import annotations

import argparse

from tb_collector.config import load_config
from tb_collector.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_collector")
    parser.add_argument("--config", required=True, help="Path to collector.yaml")
    args = parser.parse_args()
    run(load_config(args.config))


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Write the systemd unit**

`collector/systemd/tb-collector.service`:
```ini
[Unit]
Description=ThreatBrain log collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/tb-collector
ExecStart=/opt/tb-collector/venv/bin/python -m tb_collector --config /opt/tb-collector/collector.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Live local smoke test (no follow, temp log)**

Start the backend locally (from `backend/`): `./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000`.
Create `collector/collector.local.yaml` pointing at `http://localhost:8000/api/v1` with a valid ThreatBrain email/password and `log_path` set to a temp file you control (e.g. `/tmp/fake_auth.log`). Write 10 failed-password lines into that temp file, then run one non-following pass:

```bash
cd collector
printf 'Failed password for root from 203.0.113.42 port 1 ssh2\n%.0s' {1..10} > /tmp/fake_auth.log
./venv/Scripts/python.exe -c "from tb_collector.config import load_config; from tb_collector.runner import run; run(load_config('collector.local.yaml'), follow=False)"
```
Expected: prints `DETECTED brute-force from 203.0.113.42` and `posted OK: {...stages_succeeded...}`; a new threat appears in the dashboard. (Delete `collector.local.yaml` and the temp threat afterward — do not commit local creds.)

- [ ] **Step 5: Write the README usage section**

`collector/README.md` documents: install (`python -m venv venv; pip install -r requirements.txt`), configure (`cp collector.example.yaml collector.yaml`; chmod 600), run (`python -m tb_collector --config collector.yaml`), and the systemd install steps.

- [ ] **Step 6: Commit**

```bash
git add collector/tb_collector/runner.py collector/tb_collector/__main__.py collector/systemd/ collector/README.md
git commit -m "feat(collector): add tail runner, CLI entrypoint, and systemd unit"
```

---

## Phase 2 Definition of Done

- `pytest` green across models, adapter, normalizer, config, emitter.
- `python -m tb_collector --config …` tails a log and posts a real detection that lands as a threat in the dashboard (verified in the Task 6 smoke test).
- `collector/` is self-contained (own venv + requirements); `backend/` untouched.
- `collector.yaml` (real creds) is git-ignored / never committed; only `collector.example.yaml` is tracked.

## What comes next (not in this plan)

- **Phase 3 — `tb-executor`**: poll `/playbooks/approvals?pending_execution=true&action_type=block_ip`, run `iptables` behind a TDD'd IP safety guard, report via `/playbooks/approvals/{id}/execution`.
- **Phase 4 — live**: `hydra` from the attacker box against Kali, full chain, then deploy backend to `space`.
