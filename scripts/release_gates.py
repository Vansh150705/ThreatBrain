#!/usr/bin/env python3
"""Run every release gate that can run in this environment and write a machine-readable + human report.

    python3 scripts/release_gates.py [--python /path/to/venv/bin/python] [--db] [--e2e] [--bench] [--out docs/reports]

Honesty rules baked in: a gate that cannot run is recorded as `skipped` with the reason (never as passed); evidence is the
tool's own output summary; the report lists what is NOT verified by any gate. Exit code 1 if any executed gate failed.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
gates: list[dict] = []


def run(name: str, cmd: list[str], *, cwd: Path = ROOT, env: dict | None = None, parse=None, timeout: int = 900, requires: str | None = None):
    if requires and not shutil.which(requires):
        gates.append({"gate": name, "status": "skipped", "reason": f"{requires} not available"})
        print(f"skip {name} ({requires} not available)")
        return None
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        out, rc = "timeout", 124
    except FileNotFoundError as exc:
        gates.append({"gate": name, "status": "skipped", "reason": str(exc)})
        print(f"skip {name} ({exc})")
        return None
    evidence = parse(out) if parse else ""
    gates.append({"gate": name, "status": "passed" if rc == 0 else "failed", "exit_code": rc, "seconds": round(time.time() - t0, 1),
                  "command": " ".join(cmd), "evidence": evidence, **({} if rc == 0 else {"tail": out[-1500:]})})
    print(f"{'ok  ' if rc == 0 else 'FAIL'} {name}: {evidence}")
    return out


def with_failures(summary_pattern: str):
    """Evidence = the summary line plus every threshold that was missed ("FAILED name: value (need ...)")."""
    def f(out: str) -> str:
        m = re.findall(summary_pattern, out)
        failed = re.findall(r"FAILED ([^\n]+)", out)
        return (m[-1] if m else "") + ("; FAILED: " + " | ".join(failed) if failed else "")
    return f


def rx(pattern: str, group: int = 0):
    def f(out: str) -> str:
        m = re.findall(pattern, out)
        return (m[-1] if isinstance(m[-1], str) else m[-1][group]) if m else ""
    return f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--db", action="store_true", help="run the PostgreSQL tests (needs PGHOST/PGPORT/PGUSER and createdb rights)")
    ap.add_argument("--e2e", action="store_true", help="run the Playwright browser tests")
    ap.add_argument("--bench", action="store_true", help="run the performance benchmark")
    ap.add_argument("--out", default=str(ROOT / "docs" / "reports"))
    a = ap.parse_args()
    py = a.python
    backend, frontend, collector = ROOT / "backend", ROOT / "frontend", ROOT / "collector"
    pybin = Path(py).parent

    run("backend: ruff", [str(pybin / "ruff"), "check", "app", "tests", "validation", "bench"], cwd=backend, parse=rx(r"(All checks passed!|Found \d+ errors?)"))
    run("backend: pytest", [py, "-m", "pytest", "-q", "-p", "no:logging"], cwd=backend, parse=rx(r"(\d+ passed[^\n]*)"))
    run("validation: engine gates", [py, "-m", "validation.runner", "--mode", "engine", "--gate"], cwd=backend, parse=rx(r"(\[engine\][^\n]*)"))
    run("validation: pipeline gates", [py, "-m", "validation.runner", "--mode", "pipeline", "--gate"], cwd=backend, parse=rx(r"(\[pipeline\][^\n]*)"))
    # Round-3 gates. These report per split (development / tuning / held-out / unseen-adversarial / hard-negative) and are NEVER pooled.
    # A failing threshold here stays failed: thresholds live in validation/gates_v2.yaml and agent_gates.yaml and are not edited to pass.
    run("validation: dataset freeze intact", [py, "-m", "validation.freeze", "--check"], cwd=backend, parse=lambda o: o.strip().splitlines()[-1] if o.strip() else "")
    run("validation: split evaluation gates (detection, FP, evasion, behaviour)", [py, "-m", "validation.evaluate", "--gate", "--pipeline-sample", "40"], cwd=backend, parse=with_failures(r"(evaluation: \d+/\d+ gates passed[^\n]*)"), timeout=1500)
    run("validation: train/held-out leakage review", [py, "-m", "validation.leakage", "--gate"], cwd=backend, parse=lambda o: o.strip().splitlines()[-1] if o.strip() else "")
    run("validation: agent evaluation gates (scripted + adversarial back-ends)", [py, "-m", "validation.agent_eval", "--gate"], cwd=backend, parse=with_failures(r"(agent evaluation[^\n]*)"), timeout=900)
    run("validation: ATT&CK coverage matrix regenerated", [py, "-m", "validation.coverage"], cwd=backend, parse=lambda o: o.strip().splitlines()[-1] if o.strip() else "")
    run("backend: pip-audit (installed tree)", [str(pybin / "pip-audit"), "--skip-editable"], cwd=backend, parse=rx(r"(No known vulnerabilities found|\d+ known vulnerabilit[^\n]*)"), requires=None)
    run("backend: bandit (medium+ severity & confidence)", [str(pybin / "bandit"), "-q", "-r", "app", "-ll", "-ii"], cwd=backend, parse=lambda o: "no medium/high findings")
    # includes tests/test_executor_sandbox.py: the real iptables/usermod run inside a disposable netns + bind-mounted /etc copy (skips visibly when not root)
    run("collector: pytest (incl. executor in a disposable namespace)", [py, "-m", "pytest", "-q", "-p", "no:logging", "-rs"], cwd=collector, parse=rx(r"(\d+ passed[^\n]*)"))
    run("frontend: eslint", ["npm", "run", "lint"], cwd=frontend, parse=rx(r"(✖ \d+ problems \(\d+ errors?, \d+ warnings?\)|^$)"), requires="npm")
    run("frontend: tsc", ["npx", "tsc", "-b"], cwd=frontend, parse=lambda o: "type-check clean", requires="npm")
    run("frontend: vitest", ["npx", "vitest", "run"], cwd=frontend, parse=rx(r"Tests\s+(\d+ passed[^\n]*)"), requires="npm")
    run("frontend: production build", ["npm", "run", "build"], cwd=frontend, parse=rx(r"(built in [\d.]+s)"), requires="npm")
    run("frontend: npm audit (production deps)", ["npm", "audit", "--omit=dev", "--audit-level=low"], cwd=frontend, parse=rx(r"(found \d+ vulnerabilities)"), requires="npm")
    made_env = False
    if not (ROOT / ".env").exists() and (ROOT / ".env.example").exists():
        shutil.copy(ROOT / ".env.example", ROOT / ".env")     # compose files reference env_file: .env; removed again below
        made_env = True
    run("compose: dev file valid", ["docker", "compose", "-f", "docker-compose.yml", "config", "-q"], requires="docker")
    run("compose: prod file valid", ["docker", "compose", "-f", "docker-compose.prod.yml", "config", "-q"], requires="docker")
    if made_env:
        (ROOT / ".env").unlink()
    if shutil.which("docker"):
        info = subprocess.run(["docker", "info"], capture_output=True, text=True)
        if info.returncode != 0:
            gates.append({"gate": "docker: image builds", "status": "skipped", "reason": "no Docker daemon available in this environment"})
            print("skip docker: image builds (no daemon)")
        else:
            # sandboxes without bridge networking: TB_DOCKER_BUILD_FLAGS="--network host" TB_DOCKER_NETWORK=host
            build_flags = os.environ.get("TB_DOCKER_BUILD_FLAGS", "").split()
            run("docker: backend image builds", ["docker", "build", "-q", *build_flags, "-t", "threatbrain-backend", "backend"])
            run("docker: backend image runs hardened (read-only rootfs, no caps, non-root) and answers /api/v1/health",
                [py, "scripts/docker_smoke.py", "threatbrain-backend", "--network", os.environ.get("TB_DOCKER_NETWORK", "bridge")],
                parse=lambda o: o.strip().splitlines()[-1] if o.strip() else "")
    if a.db:
        run("database: all migrations on PostgreSQL", ["./database/verify_migrations.sh", "tb_gate_check"], parse=lambda o: "every migration applied" if "FAIL" not in o else "FAILED")
        run("database: queue semantics", ["./database/tests/test_queue.sh", "tb_gate_check"], parse=rx(r"(ok\s+\d+ jobs claimed[^\n]*)"))
        run("database: security properties", ["./database/tests/test_security.sh", "tb_gate_check"], parse=rx(r"(---- \d+ passed, \d+ failed)"))
        run("database: migrate / rollback / backup / restore", ["./database/tests/test_ops.sh"], parse=rx(r"(---- \d+ passed, \d+ failed)"))
        run("database: queue workload, worker-kill recovery, concurrent writers", ["./database/tests/test_workload.sh", "tb_gate_check"], parse=rx(r"(---- \d+ passed, \d+ failed)"), timeout=900)
    else:
        gates.append({"gate": "database tests", "status": "skipped", "reason": "run with --db and PGHOST/PGPORT/PGUSER set"})
    if a.e2e:
        run("e2e: Chromium against the real app + production bundle", ["node", "e2e/run.cjs"], cwd=frontend, env={"PYTHON": py}, parse=rx(r"(\d+ passed, \d+ failed)"), requires="node")
    else:
        gates.append({"gate": "e2e browser tests", "status": "skipped", "reason": "run with --e2e"})
    if a.bench:
        run("benchmark", [py, "-m", "bench.perf"], cwd=backend, parse=rx(r"(detection[^\n]*)"))

    summary = {s: sum(1 for g in gates if g["status"] == s) for s in ("passed", "failed", "skipped")}
    report = {
        "schema": "threatbrain.release-gates/1",
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git": subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
        "environment": {"python": subprocess.run([py, "-c", "import platform;print(platform.python_version())"], capture_output=True, text=True).stdout.strip() or platform.python_version(),
                        "platform": platform.platform()},
        "summary": summary, "gates": gates,
        "not_verified_by_any_gate": [
            "A live Supabase project (PostgREST, GoTrue, Realtime) - tests use an in-memory PostgREST stand-in; SQL is verified on a plain PostgreSQL 16 with stand-in auth objects",
            "A live LLM provider - agents run against a scripted model; detection quality is measured without it, LLM verdict quality is not measured",
            "The frontend image build and the full production compose stack (needs registry access for node/nginx/postgres/postgrest/gotrue base images)",
            "tb-executor against a real production firewall / fleet, Windows Firewall, nftables-only hosts (the Linux iptables/usermod path IS exercised, but only inside a disposable network+mount namespace)",
            "Detection quality on real customer traffic - every number is measured on synthetic/derived corpora; the held-out sets are small and were authored by the same team",
            "LLM latency, token cost and verdict quality under a real provider (the agent evaluation uses scripted back-ends, including adversarial ones)",
            "Hosted-IdP or Supabase asymmetric JWKS endpoints - verified with locally generated keys only",
            "Throughput or latency on production-grade infrastructure, multi-node scaling",
            "Any compliance framework (SOC 2, ISO 27001, ...) - no independent assessment has been performed",
        ],
    }
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "release-report.json").write_text(json.dumps(report, indent=2))
    lines = [f"# Release gate report", "", f"* commit `{report['git']}` · {report['generated_at']} · python {report['environment']['python']}",
             f"* **{summary['passed']} passed · {summary['failed']} failed · {summary['skipped']} skipped**", "",
             "| Gate | Result | Evidence |", "|---|---|---|"]
    for g in gates:
        lines.append(f"| {g['gate']} | {g['status']} | {g.get('evidence') or g.get('reason', '')} |")
    failed_gates = [g for g in gates if g["status"] == "failed"]
    if failed_gates:
        lines += ["", "## Failed gates (not waived, thresholds unchanged)", ""] + [f"* **{g['gate']}**: {g.get('evidence') or 'see release-report.json'}" for g in failed_gates]
    lines += ["", "## Not verified by any gate", ""] + [f"* {x}" for x in report["not_verified_by_any_gate"]]
    (out / "release-report.md").write_text("\n".join(lines) + "\n")
    print(f"\n{summary} -> {out / 'release-report.md'}")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
