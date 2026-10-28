"""Configuration + environment self-check: ``python -m app.doctor [--json]``. Exit code 1 if any check fails."""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        from app.core.config import get_settings

        get_settings()
    except Exception as exc:  # pydantic ValidationError / production guard: print every problem clearly
        msg = str(exc)
        if "--json" in sys.argv:
            print(json.dumps({"ok": False, "results": [{"status": "fail", "check": "configuration", "detail": msg, "fix": "Fix the listed variables in .env"}]}))
        else:
            print("FAIL configuration is invalid:\n  " + msg.replace("\n", "\n  "))
        return 1
    from app.services import ops_service

    results = ops_service.doctor()
    ok = not any(r["status"] == "fail" for r in results)
    if "--json" in sys.argv:
        print(json.dumps({"ok": ok, "results": results}, indent=2))
    else:
        icons = {"ok": "ok  ", "warn": "WARN", "fail": "FAIL"}
        for r in results:
            print(f"{icons[r['status']]} {r['check']}: {r['detail']}")
            if r["status"] != "ok" and r["fix"]:
                print(f"       fix: {r['fix']}")
        print("\n" + ("healthy" if ok else "NOT healthy: fix the FAIL items above"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
