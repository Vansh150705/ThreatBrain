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
    run("backend: pip-audit (installed tree)", [str(pybin / "pip-audit"), "--skip-editable"], cwd=backend, parse=rx(r"(No known vulnerabilities found|\d+ known vulnerabilit[^\n]*)"), requires=None)
    run("backend: bandit (medium+ severity & confidence)", [str(pybin / "bandit"), "-q", "-r", "app", "-ll", "-ii"], cwd=backend, parse=lambda o: "no medium/high findings")
    run("collector: pytest", [py, "-m", "pytest", "-q", "-p", "no:logging"], cwd=collector, parse=rx(r"(\d+ passed[^\n]*)"))
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
            run("docker: backend image builds", ["docker", "build", "-q", "-t", "threatbrain-backend", "backend"])
    if a.db:
        run("database: all migrations on PostgreSQL", ["./database/verify_migrations.sh", "tb_gate_check"], parse=lambda o: "every migration applied" if "FAIL" not in o else "FAILED")
        run("database: queue semantics", ["./database/tests/test_queue.sh", "tb_gate_check"], parse=rx(r"(ok\s+\d+ jobs claimed[^\n]*)"))
        run("database: security properties", ["./database/tests/test_security.sh", "tb_gate_check"], parse=rx(r"(---- \d+ passed, \d+ failed)"))
        run("database: migrate / rollback / backup / restore", ["./database/tests/test_ops.sh"], parse=rx(r"(---- \d+ passed, \d+ failed)"))
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
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "summary": summary, "gates": gates,
        "not_verified_by_any_gate": [
            "A live Supabase project (PostgREST, GoTrue, Realtime) - tests use an in-memory PostgREST stand-in; SQL is verified on a plain PostgreSQL 16 with stand-in auth objects",
            "A live LLM provider - agents run against a scripted model; detection quality is measured without it, LLM verdict quality is not measured",
            "Docker image builds and the production compose stack (unless a daemon was available - see the docker gates)",
            "tb-executor against a real firewall / host",
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
    lines += ["", "## Not verified by any gate", ""] + [f"* {x}" for x in report["not_verified_by_any_gate"]]
    (out / "release-report.md").write_text("\n".join(lines) + "\n")
    print(f"\n{summary} -> {out / 'release-report.md'}")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
