# Real Attack Ingestion — Phase 3 (tb-executor) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Build `tb-executor`, a standalone daemon that polls the backend for approved `block_ip` actions, blocks the IP on the host with `iptables` (behind a safety guard), and reports the result back.

**Architecture:** Poll-based, outbound-only (works behind NAT). The runner asks the backend for approved-but-unexecuted `block_ip` actions, runs each target IP through a pure `is_blockable_ip` guard, blocks it via an injectable blocker (`IptablesBlocker` on Linux, `DryRunBlocker` for testing/safety), then reports `executed`/`failed`. Guard, client, and runner are unit-tested with fakes; the real `iptables` call runs only on the host.

**Tech Stack:** Python 3.11, `requests`, `PyYAML`; `pytest`. Lives beside the collector under `collector/tb_executor/`, sharing the collector's venv.

## Global Constraints

- New code under `collector/tb_executor/`. Do not modify `backend/` or `tb_collector/`.
- Commit style: Conventional Commits; author = repo owner only (no Claude co-author).
- The executor only ever acts on approvals a human already set to `status='approved'`; it never approves anything itself.
- The guard MUST refuse loopback, private (RFC1918), link-local, multicast, unspecified, and allowlisted IPs, and any non-IP string.
- Backend contract (from Phase 1): `GET /playbooks/approvals?pending_execution=true&action_type=block_ip` returns `{items:[{id,target,...}]}`; `POST /playbooks/approvals/{id}/execution` body `{result:"executed"|"failed", detail?}`.

---

### Task 1: IP safety guard — TDD

**Files:** Create `collector/tb_executor/__init__.py`, `collector/tb_executor/guard.py`; Test `collector/tests/test_guard.py`.

**Interfaces:** Produces `is_blockable_ip(ip: str, allowlist: Iterable[str] = ()) -> tuple[bool, str]`.

- [ ] **Step 1: failing tests** — `collector/tests/test_guard.py`:
```python
from tb_executor.guard import is_blockable_ip


def test_public_ip_is_blockable():
    ok, _ = is_blockable_ip("203.0.113.42")
    assert ok is True


def test_loopback_rejected():
    ok, reason = is_blockable_ip("127.0.0.1")
    assert ok is False and "loopback" in reason


def test_private_ranges_rejected():
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.0.1"):
        ok, _ = is_blockable_ip(ip)
        assert ok is False


def test_link_local_rejected():
    ok, _ = is_blockable_ip("169.254.10.10")
    assert ok is False


def test_allowlisted_ip_rejected():
    ok, reason = is_blockable_ip("203.0.113.42", allowlist=["203.0.113.42"])
    assert ok is False and "allowlist" in reason


def test_garbage_rejected():
    ok, reason = is_blockable_ip("not-an-ip")
    assert ok is False and "valid" in reason
```

- [ ] **Step 2: run, expect fail** — `cd collector && ./venv/Scripts/python.exe -m pytest tests/test_guard.py -q`

- [ ] **Step 3: implement** — `collector/tb_executor/__init__.py` (empty) and `collector/tb_executor/guard.py`:
```python
from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def is_blockable_ip(ip: str, allowlist: Iterable[str] = ()) -> tuple[bool, str]:
    """Return (blockable, reason). Refuses anything unsafe to firewall-drop."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"not a valid IP: {ip!r}"
    if str(addr) in set(allowlist):
        return False, "IP is allowlisted"
    if addr.is_loopback:
        return False, "loopback address"
    if addr.is_private:
        return False, "private/RFC1918 address"
    if addr.is_link_local:
        return False, "link-local address"
    if addr.is_multicast:
        return False, "multicast address"
    if addr.is_unspecified:
        return False, "unspecified address"
    return True, "ok"
```

- [ ] **Step 4: run, expect pass**; **Step 5: commit** `feat(executor): add IP safety guard`

---

### Task 2: Blocker (iptables + dry-run)

**Files:** Create `collector/tb_executor/blocker.py`; Test `collector/tests/test_blocker.py`.

**Interfaces:** `DryRunBlocker().block(ip) -> str` (records to `.blocked`); `IptablesBlocker(chain="INPUT").block(ip) -> str` (idempotent; real subprocess, not unit-tested).

- [ ] **Step 1: failing test** — `collector/tests/test_blocker.py`:
```python
from tb_executor.blocker import DryRunBlocker


def test_dry_run_records_and_reports():
    b = DryRunBlocker()
    msg = b.block("203.0.113.42")
    assert "203.0.113.42" in msg
    assert b.blocked == ["203.0.113.42"]
```

- [ ] **Step 2: run, expect fail**; **Step 3: implement** — `collector/tb_executor/blocker.py`:
```python
from __future__ import annotations

import subprocess


class DryRunBlocker:
    """Records intended blocks without touching the firewall."""

    def __init__(self) -> None:
        self.blocked: list[str] = []

    def block(self, ip: str) -> str:
        self.blocked.append(ip)
        return f"[dry-run] would block {ip}"


class IptablesBlocker:
    """Adds an iptables DROP rule for a source IP (idempotent). Linux only."""

    def __init__(self, chain: str = "INPUT") -> None:
        self.chain = chain

    def _rule_exists(self, ip: str) -> bool:
        result = subprocess.run(
            ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True,
        )
        return result.returncode == 0

    def block(self, ip: str) -> str:
        if self._rule_exists(ip):
            return f"already blocked {ip}"
        subprocess.run(
            ["iptables", "-A", self.chain, "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
        )
        return f"iptables DROP added for {ip}"
```

- [ ] **Step 4: run, expect pass**; **Step 5: commit** `feat(executor): add iptables and dry-run blockers`

---

### Task 3: API client — TDD with a fake HTTP

**Files:** Create `collector/tb_executor/client.py`; Test `collector/tests/test_executor_client.py`.

**Interfaces:** `ExecutorClient(base_url, email, password, http=None)` with `list_pending_blocks() -> list[dict]` and `report(approval_id, result, detail=None) -> dict`; re-logs-in once on 401.

- [ ] **Step 1: failing tests** — `collector/tests/test_executor_client.py`:
```python
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


def test_list_pending_blocks_logs_in_and_returns_items():
    http = FakeHttp()
    http.login_responses = [FakeResp(200, {"access_token": "tok"})]
    http.get_responses = [FakeResp(200, {"items": [{"id": "a1", "target": "203.0.113.42"}]})]
    c = ExecutorClient("http://x/api/v1", "e@x.co", "pw", http=http)
    items = c.list_pending_blocks()
    assert items == [{"id": "a1", "target": "203.0.113.42"}]
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
```

- [ ] **Step 2: run, expect fail**; **Step 3: implement** — `collector/tb_executor/client.py`:
```python
from __future__ import annotations

from typing import Any


class ExecutorError(Exception):
    pass


class ExecutorClient:
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
            raise ExecutorError(f"login failed: {resp.status_code}")
        self._token = resp.json()["access_token"]

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    def list_pending_blocks(self) -> list[dict[str, Any]]:
        if self._token is None:
            self._login()
        resp = self.http.get(
            f"{self.base_url}/playbooks/approvals",
            params={"pending_execution": "true", "action_type": "block_ip"},
            headers=self._headers(),
            timeout=30,
        )
        if resp.status_code == 401:
            self._login()
            resp = self.http.get(
                f"{self.base_url}/playbooks/approvals",
                params={"pending_execution": "true", "action_type": "block_ip"},
                headers=self._headers(),
                timeout=30,
            )
        if resp.status_code != 200:
            raise ExecutorError(f"list failed: {resp.status_code}")
        return resp.json().get("items", [])

    def report(self, approval_id: str, result: str, detail: str | None = None) -> dict[str, Any]:
        if self._token is None:
            self._login()
        url = f"{self.base_url}/playbooks/approvals/{approval_id}/execution"
        payload = {"result": result, "detail": detail}
        resp = self.http.post(url, json=payload, headers=self._headers(), timeout=30)
        if resp.status_code == 401:
            self._login()
            resp = self.http.post(url, json=payload, headers=self._headers(), timeout=30)
        if resp.status_code != 200:
            raise ExecutorError(f"report failed: {resp.status_code}")
        return resp.json()
```

- [ ] **Step 4: run, expect pass**; **Step 5: commit** `feat(executor): add backend API client for approvals`

---

### Task 4: Config + runner — TDD the loop with fakes

**Files:** Create `collector/tb_executor/config.py`, `collector/tb_executor/runner.py`, `collector/tb_executor/__main__.py`, `collector/executor.example.yaml`, `collector/systemd/tb-executor.service`; Test `collector/tests/test_executor_runner.py`.

**Interfaces:** `ExecutorConfig{base_url,email,password,poll_interval=10,dry_run=True,firewall="iptables",allowlist=()}`; `load_executor_config(path)`; `run(config, *, client=None, blocker=None, iterations=None)`.

- [ ] **Step 1: failing tests** — `collector/tests/test_executor_runner.py`:
```python
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


def _cfg():
    return ExecutorConfig(base_url="x", email="e", password="p")


def test_runner_blocks_public_ip_and_reports_executed():
    client = FakeClient([{"id": "a1", "target": "203.0.113.42"}])
    blocker = DryRunBlocker()
    run(_cfg(), client=client, blocker=blocker, iterations=1)
    assert blocker.blocked == ["203.0.113.42"]
    assert client.reports == [("a1", "executed", "[dry-run] would block 203.0.113.42")]


def test_runner_rejects_private_ip_and_reports_failed():
    client = FakeClient([{"id": "a2", "target": "10.0.0.5"}])
    run(_cfg(), client=client, blocker=DryRunBlocker(), iterations=1)
    assert client.reports[0][0] == "a2"
    assert client.reports[0][1] == "failed"
```

- [ ] **Step 2: run, expect fail**; **Step 3: implement**:

`collector/tb_executor/config.py`:
```python
from __future__ import annotations

from dataclasses import dataclass, field

import yaml


@dataclass
class ExecutorConfig:
    base_url: str
    email: str
    password: str
    poll_interval: int = 10
    dry_run: bool = True
    firewall: str = "iptables"
    allowlist: tuple[str, ...] = field(default_factory=tuple)


def load_executor_config(path: str) -> ExecutorConfig:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return ExecutorConfig(
        base_url=data["base_url"],
        email=data["email"],
        password=data["password"],
        poll_interval=int(data.get("poll_interval", 10)),
        dry_run=bool(data.get("dry_run", True)),
        firewall=data.get("firewall", "iptables"),
        allowlist=tuple(data.get("allowlist", []) or []),
    )
```

`collector/tb_executor/runner.py`:
```python
from __future__ import annotations

import time

from tb_executor.blocker import DryRunBlocker, IptablesBlocker
from tb_executor.client import ExecutorClient
from tb_executor.config import ExecutorConfig
from tb_executor.guard import is_blockable_ip


def run(config: ExecutorConfig, *, client=None, blocker=None, iterations=None) -> None:
    if client is None:
        client = ExecutorClient(config.base_url, config.email, config.password)
    if blocker is None:
        blocker = DryRunBlocker() if config.dry_run else IptablesBlocker()

    mode = "DRY-RUN" if isinstance(blocker, DryRunBlocker) else "LIVE"
    print(f"[tb-executor] polling {config.base_url} every {config.poll_interval}s ({mode})")

    i = 0
    while iterations is None or i < iterations:
        try:
            pending = client.list_pending_blocks()
        except Exception as exc:
            print(f"[tb-executor] poll failed: {exc}")
            pending = []

        for item in pending:
            ip = item.get("target", "")
            ok, reason = is_blockable_ip(ip, config.allowlist)
            if not ok:
                print(f"[tb-executor] REFUSED {ip}: {reason}")
                client.report(item["id"], "failed", f"guard refused: {reason}")
                continue
            try:
                detail = blocker.block(ip)
                print(f"[tb-executor] BLOCKED {ip}: {detail}")
                client.report(item["id"], "executed", detail)
            except Exception as exc:
                print(f"[tb-executor] block failed for {ip}: {exc}")
                client.report(item["id"], "failed", str(exc))

        i += 1
        if iterations is None:
            time.sleep(config.poll_interval)
```

`collector/tb_executor/__main__.py`:
```python
from __future__ import annotations

import argparse

from tb_executor.config import load_executor_config
from tb_executor.runner import run


def main() -> None:
    parser = argparse.ArgumentParser(prog="tb_executor")
    parser.add_argument("--config", required=True, help="Path to executor.yaml")
    args = parser.parse_args()
    run(load_executor_config(args.config))


if __name__ == "__main__":
    main()
```

`collector/executor.example.yaml`:
```yaml
# Copy to executor.yaml and fill in. Then: chmod 600 executor.yaml
base_url: https://vansh150705-threatbrain-backend.hf.space/api/v1
email: you@example.com
password: your-threatbrain-password
poll_interval: 10
# dry_run: true logs intended blocks without touching iptables. Set false to really block.
dry_run: true
firewall: iptables
# never block these (your own IP / management hosts):
allowlist:
  - 203.0.113.9
```

`collector/systemd/tb-executor.service`:
```ini
[Unit]
Description=ThreatBrain response executor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/tb-collector
ExecStart=/opt/tb-collector/venv/bin/python -m tb_executor --config /opt/tb-collector/executor.yaml
Restart=always
RestartSec=5
# needs root to run iptables
User=root

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: run full suite, expect pass** — `cd collector && ./venv/Scripts/python.exe -m pytest -q`
- [ ] **Step 5: update `.gitignore`** to ignore `executor.yaml` and `executor.local.yaml`.
- [ ] **Step 6: commit** `feat(executor): add config loader, poll runner, CLI, and systemd unit`

---

## Phase 3 Definition of Done

- `pytest` green across guard, blocker, client, runner.
- `python -m tb_executor --config executor.yaml` polls approved `block_ip` actions, guards the target, blocks (or dry-runs), and reports back.
- Real creds (`executor.yaml`) git-ignored; only `executor.example.yaml` tracked.

## What comes next (Phase 4 — live, on Kali)

1. Deploy the backend changes to HF Spaces (push `backend/` to the `space` remote) so the collector/executor can reach the live API. Apply migration 021 (already applied to Supabase).
2. On Kali: install collector + executor, fill in `collector.yaml` / `executor.yaml`, start both.
3. From the attacker box: `hydra -l root -P <wordlist> ssh://<kali-ip>`.
4. Watch a threat + incident + block recommendation appear; approve it in `/approvals`; watch tb-executor run the real `iptables` DROP and the attack stop; confirm the audit trail.
