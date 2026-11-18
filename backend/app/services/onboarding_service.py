"""First-run experience: a checklist computed from real state, and a one-click synthetic demo campaign."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from app.agents.triage import TriageInput
from app.core.config import get_settings
from app.services import ingest_service, llm_service
from app.services.supabase_client import get_supabase_admin

CAMPAIGN = Path(__file__).resolve().parent.parent / "demo" / "campaign.yaml"
DEMO_SOURCE = "demo"


def _count(table: str, org_id: str, col: str = "id", **eq: Any) -> int:
    q = get_supabase_admin().table(table).select(col, count="exact").eq("organization_id", org_id)
    for k, v in eq.items():
        q = q.eq(k, v)
    return q.limit(1).execute().count or 0


def checklist(org_id: str) -> dict[str, Any]:
    client = get_supabase_admin()
    keys = client.table("api_keys").select("scopes, last_used_at, revoked_at").eq("organization_id", org_id).execute().data or []
    live = [k for k in keys if not k.get("revoked_at")]
    real_events = [e for e in (client.table("events").select("source_system").eq("organization_id", org_id).limit(500).execute().data or [])
                   if e.get("source_system") != f"{DEMO_SOURCE}"]
    steps = [
        {"id": "llm", "title": "Connect a language model (optional: rules-only mode works without one)",
         "done": llm_service.llm_configured(), "where": "Server environment: GROQ_API_KEY or LLM_PROVIDER"},
        {"id": "api_key", "title": "Create an ingest API key", "done": any("ingest" in (k.get("scopes") or []) for k in live), "where": "Settings -> API keys"},
        {"id": "first_event", "title": "Send your first real event", "done": bool(real_events), "where": "tb-collector or POST /api/v1/ingest/event"},
        {"id": "first_threat", "title": "See a detection become a threat", "done": _count("threats", org_id) > 0, "where": "Threats"},
        {"id": "executor", "title": "Connect tb-executor (only if you want approved actions to run)", "done": any("executor" in (k.get("scopes") or []) and k.get("last_used_at") for k in live), "where": "collector/README.md"},
        {"id": "rules", "title": "Review detection rules and silence what is noisy in your environment",
         "done": _count("rule_overrides", org_id, "rule_key") + _count("detection_rules", org_id) > 0, "where": "Detection -> Rules"},
        {"id": "team", "title": "Invite the rest of the SOC team", "done": _count("users", org_id) > 1, "where": "Settings -> Members"},
    ]
    nxt = next((s for s in steps if not s["done"] and s["id"] != "executor"), None)
    done = sum(1 for s in steps if s["done"])
    return {"steps": steps, "completed": done, "total": len(steps), "next": nxt["id"] if nxt else None,
            "demo_loaded": any(e.get("source_system") == DEMO_SOURCE for e in
                               (client.table("events").select("source_system").eq("organization_id", org_id).eq("source_system", DEMO_SOURCE).limit(1).execute().data or []))}


def load_demo(org_id: str) -> dict[str, Any]:
    """Ingest the synthetic campaign (timestamps relative to now) through the normal pipeline."""
    if not get_settings().ALLOW_DEMO_LOAD:
        raise PermissionError("Demo data loading is disabled on this deployment (ALLOW_DEMO_LOAD=false).")
    raw = yaml.safe_load(CAMPAIGN.read_text(encoding="utf-8"))["events"]
    now = datetime.now(UTC)
    events = []
    for item in raw:
        ev = {k: v for k, v in item.items() if k != "ago"}
        ev["occurred_at"] = (now - timedelta(minutes=item["ago"])).isoformat()
        ev.setdefault("raw_data", {})["demo"] = True
        events.append(TriageInput.model_validate(ev))
    out = ingest_service.accept_events(org_id, events, source_system=DEMO_SOURCE)
    return {**out, "total_events": len(events), "note": "Processed asynchronously by the worker; refresh Threats in a few seconds."}
