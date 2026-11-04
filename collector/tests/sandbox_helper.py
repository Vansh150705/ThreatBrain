"""Runs INSIDE a throw-away network + mount namespace (see test_executor_sandbox.py). Prints one JSON object of observations.

Nothing here can touch the host: iptables rules live in the new network namespace, and /etc is a bind-mounted COPY, so account changes
are made to the copy. The host's state is re-checked by the parent test afterwards.
"""

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.environ["TB_COLLECTOR_DIR"])
from tb_executor.actions import ActionDispatcher  # noqa: E402


def sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True).stdout


def main() -> None:
    sandbox_etc = os.environ["TB_SANDBOX_ETC"]
    shutil.rmtree(sandbox_etc, ignore_errors=True)
    subprocess.run(["cp", "-a", "/etc/.", sandbox_etc], check=True)
    subprocess.run(["mount", "--bind", sandbox_etc, "/etc"], check=True)
    subprocess.run(["useradd", "-M", "-s", "/usr/sbin/nologin", "tbvictim"], check=True)
    obs: dict = {}
    live = ActionDispatcher(enabled_actions={"block_ip", "block_range", "disable_user"}, dry_run=False, firewall="iptables",
                            ip_allowlist=["185.220.101.250"], user_allowlist=["tbkeep"])
    obs["mode"] = live.mode()
    obs["block_public"] = live.handle("block_ip", "185.220.101.9")
    obs["block_again"] = live.handle("block_ip", "185.220.101.9")
    obs["block_private"] = live.handle("block_ip", "10.0.0.5")
    obs["block_loopback"] = live.handle("block_ip", "127.0.0.1")
    obs["block_allowlisted"] = live.handle("block_ip", "185.220.101.250")
    obs["block_garbage"] = live.handle("block_ip", "185.220.101.9; reboot")
    obs["block_option_injection"] = live.handle("block_ip", "-j ACCEPT")
    obs["block_range_24"] = live.handle("block_range", "185.220.102.0/24")
    obs["block_range_8"] = live.handle("block_range", "198.0.0.0/8")
    obs["block_range_everything"] = live.handle("block_range", "0.0.0.0/0")
    obs["block_ipv6"] = live.handle("block_ip", "2a0b:f4c0::bad")
    obs["disable_victim"] = live.handle("disable_user", "tbvictim")
    obs["disable_root"] = live.handle("disable_user", "root")
    obs["disable_option_injection"] = live.handle("disable_user", "-h")
    obs["disable_allowlisted"] = live.handle("disable_user", "tbkeep")
    obs["not_enabled"] = ActionDispatcher(enabled_actions={"block_ip"}, dry_run=False, firewall="iptables").handle("disable_user", "tbvictim")
    obs["unsupported"] = live.handle("isolate_host", "web-01")
    obs["iptables_rules"] = sh("iptables", "-S", "INPUT").splitlines()
    obs["ip6tables_rules"] = sh("ip6tables", "-S", "INPUT").splitlines()
    obs["shadow_victim"] = next((ln.split(":")[1][:1] for ln in open("/etc/shadow") if ln.startswith("tbvictim:")), None)
    obs["shadow_root_locked"] = next((ln.split(":")[1].startswith("!") for ln in open("/etc/shadow") if ln.startswith("root:")), None)
    before = sh("iptables", "-S", "INPUT")
    dry = ActionDispatcher(enabled_actions={"block_ip", "disable_user"}, dry_run=True)
    obs["dry_mode"] = dry.mode()
    obs["dry_block"] = dry.handle("block_ip", "185.220.101.77")
    obs["dry_disable"] = dry.handle("disable_user", "tbvictim")
    obs["dry_run_changed_rules"] = sh("iptables", "-S", "INPUT") != before
    print(json.dumps(obs))


main()
