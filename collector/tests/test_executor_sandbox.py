"""tb-executor in LIVE mode inside a disposable network + mount namespace.

VERIFIED HERE: the real iptables / ip6tables / usermod commands, run by the real dispatcher, with the guards, idempotency and dry-run
behaviour; the host's firewall and /etc are re-checked afterwards.
NOT VERIFIED HERE: a real production firewall or fleet (never tested on one, by design), Windows Firewall / `net user`, nftables-only hosts,
or the executor's polling/approval protocol against a live server (covered by mocks in test_executor_client.py).
Skipped, visibly, unless running as root with `unshare`, `iptables` and `usermod` available.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
NEEDED = ("unshare", "iptables", "ip6tables", "usermod", "useradd")

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or any(shutil.which(b) is None for b in NEEDED),
    reason="needs root and unshare/iptables/ip6tables/usermod/useradd to build a disposable namespace",
)


def host_rules() -> str:
    return subprocess.run(["iptables", "-S", "INPUT"], capture_output=True, text=True).stdout


@pytest.fixture(scope="module")
def observed(tmp_path_factory):
    before_rules = host_rules()
    before_passwd = Path("/etc/passwd").read_text()
    sandbox_etc = tmp_path_factory.mktemp("sbx") / "etc"
    sandbox_etc.mkdir()
    env = {**os.environ, "TB_COLLECTOR_DIR": str(HERE.parent), "TB_SANDBOX_ETC": str(sandbox_etc)}
    p = subprocess.run(["unshare", "--net", "--mount", "--", sys.executable, str(HERE / "sandbox_helper.py")], capture_output=True, text=True, env=env, timeout=60)
    if p.returncode != 0:
        pytest.skip(f"the kernel/container does not allow the sandbox namespaces: {p.stderr.strip()[-300:]}")
    obs = json.loads(p.stdout.strip().splitlines()[-1])
    obs["_host_rules_unchanged"] = host_rules() == before_rules
    obs["_host_passwd_unchanged"] = Path("/etc/passwd").read_text() == before_passwd and "tbvictim" not in Path("/etc/shadow").read_text()
    return obs


def test_the_host_was_never_touched(observed):
    assert observed["_host_rules_unchanged"] and observed["_host_passwd_unchanged"]


def test_public_attacker_is_blocked_once_and_idempotently(observed):
    assert observed["mode"] == "LIVE"
    assert observed["block_public"][0] == "executed" and "DROP added" in observed["block_public"][1]
    assert tuple(observed["block_again"]) == ("executed", "already blocked 185.220.101.9")
    assert sum("185.220.101.9" in r for r in observed["iptables_rules"]) == 1


@pytest.mark.parametrize("key", ["block_private", "block_loopback", "block_allowlisted", "block_garbage", "block_option_injection", "block_range_8", "block_range_everything"])
def test_guards_refuse_dangerous_or_malformed_targets_before_any_command_runs(observed, key):
    assert observed[key][0] == "failed" and "guard refused" in observed[key][1]
    rules = " ".join(observed["iptables_rules"])
    assert "10.0.0.5" not in rules and "127.0.0.1" not in rules and "185.220.101.250" not in rules and "0.0.0.0/0" not in rules and "198.0.0.0/8" not in rules


def test_ranges_and_ipv6_use_the_right_tool(observed):
    assert observed["block_range_24"][0] == "executed" and any("185.220.102.0/24" in r for r in observed["iptables_rules"])
    assert observed["block_ipv6"][0] == "executed" and any("2a0b:f4c0::bad" in r for r in observed["ip6tables_rules"])


def test_account_lock_is_applied_in_the_sandbox_and_protected_accounts_refused(observed):
    assert observed["disable_victim"][0] == "executed" and observed["shadow_victim"] == "!"
    assert observed["disable_root"][0] == "failed" and observed["shadow_root_locked"] is False
    assert observed["disable_option_injection"][0] == "failed" and observed["disable_allowlisted"][0] == "failed"


def test_actions_the_operator_did_not_enable_do_nothing(observed):
    assert observed["not_enabled"][0] == "failed" and "not enabled" in observed["not_enabled"][1]
    assert observed["unsupported"][0] == "failed"


def test_dry_run_changes_nothing(observed):
    assert observed["dry_mode"] == "DRY-RUN" and observed["dry_block"][1].startswith("[dry-run]") and observed["dry_run_changed_rules"] is False
