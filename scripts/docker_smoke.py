#!/usr/bin/env python3
"""Run the built backend image with the production hardening profile and check that it serves /api/v1/health.

    python3 scripts/docker_smoke.py <image> [--network host]

Hardening profile = the one in docker-compose.prod.yml: read-only root filesystem, tmpfs /tmp, all capabilities dropped,
no-new-privileges, non-root user. This proves the *image* starts under that profile. It does NOT prove the stack
(Supabase, nginx, frontend) works - no database is attached; /health only reports liveness.
Exit 0 on success, 1 on failure, 2 if no Docker daemon is reachable (the release script records that as skipped/failed explicitly).
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
import urllib.request


def sh(*a: str) -> subprocess.CompletedProcess:
    return subprocess.run(list(a), capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--network", default="bridge", help="'bridge' normally; 'host' for sandboxes without bridge networking (the port is picked free)")
    a = ap.parse_args()
    if sh("docker", "info").returncode != 0:
        print("no Docker daemon reachable")
        return 2
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    name = f"tb-smoke-{port}"
    publish = [] if a.network == "host" else ["-p", f"127.0.0.1:{port}:{port}"]
    run = sh("docker", "run", "-d", "--name", name, "--network", a.network, *publish, "--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges:true", "-e", f"PORT={port}", "-e", "APP_ENV=development",
             "-e", "SUPABASE_URL=https://example.invalid", "-e", "SUPABASE_SERVICE_ROLE_KEY=smoke-test-not-a-secret", "-e", "SUPABASE_ANON_KEY=smoke-test-not-a-secret",
             "-e", "SUPABASE_JWT_SECRET=smoke-test-not-a-secret-smoke-test-not-a-secret", a.image)
    if run.returncode != 0:
        print(f"docker run failed: {run.stderr.strip()[-300:]}")
        return 1
    ok, detail = False, "no response"
    try:
        for _ in range(60):
            time.sleep(1)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=2) as r:
                    body = json.loads(r.read() or b"{}")
                    ok, detail = r.status == 200, f"HTTP {r.status} {json.dumps(body)[:120]}"
                    break
            except Exception as exc:   # still starting
                detail = type(exc).__name__
        info = json.loads(sh("docker", "inspect", name).stdout)[0]
        hc = info["HostConfig"]
        user = (info["Config"].get("User") or "root")
        checks = {"read-only rootfs": hc.get("ReadonlyRootfs") is True, "caps dropped": "ALL" in (hc.get("CapDrop") or []),
                  "no-new-privileges": "no-new-privileges:true" in (hc.get("SecurityOpt") or []), "non-root user": user not in ("", "root", "0")}
        bad = [k for k, v in checks.items() if not v]
        if bad:
            ok, detail = False, f"hardening not applied: {', '.join(bad)}"
        else:
            detail = f"{detail}; " + ", ".join(checks)
    finally:
        sh("docker", "rm", "-f", name)
    print(("image runs hardened: " if ok else "FAILED: ") + detail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
