"""SOC performance metrics computed from the organization's own data."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any

from app.services.supabase_client import get_supabase_admin

_ROW_CAP = 5000  # bound the work per request; the response reports when it was hit


def _parse(ts: Any) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _mins(delta: timedelta) -> float:
    return round(delta.total_seconds() / 60, 1)


def compute(org_id: str, days: int = 7) -> dict[str, Any]:
    client = get_supabase_admin()
    now = datetime.now(UTC)
    since = (now - timedelta(days=days)).isoformat()

    threats = (
        client.table("threats")
        .select("short_id, severity, status, risk_score, detected_at, created_at, event_count, source_ips, mitre_techniques, mitre_tactics, incident_id")
        .eq("organization_id", org_id).is_("deleted_at", "null").gte("detected_at", since)
        .order("detected_at", desc=True).limit(_ROW_CAP).execute().data or []
    )
    incidents = (
        client.table("incidents")
        .select("short_id, severity, status, priority, first_seen_at, last_seen_at, created_at, contained_at, resolved_at, assigned_to")
        .eq("organization_id", org_id).is_("deleted_at", "null").gte("created_at", since)
        .order("created_at", desc=True).limit(_ROW_CAP).execute().data or []
    )
    open_incidents = (
        client.table("incidents").select("id, status, severity, assigned_to", count="exact")
        .eq("organization_id", org_id).is_("deleted_at", "null")
        .in_("status", ["open", "investigating", "contained"]).limit(_ROW_CAP).execute()
    )
    runs = (
        client.table("agent_runs")
        .select("agent_key, status, latency_ms, total_tokens, created_at")
        .eq("organization_id", org_id).gte("created_at", since).limit(_ROW_CAP).execute().data or []
    )
    approvals = (
        client.table("playbook_approvals")
        .select("status, execution_status, created_at, decided_at")
        .eq("organization_id", org_id).gte("created_at", since).limit(_ROW_CAP).execute().data or []
    )

    # ---- severity + daily series
    sev = Counter(t["severity"] for t in threats)
    per_day: dict[str, Counter] = {}
    for i in range(days):
        per_day[(now - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")] = Counter()
    for t in threats:
        dt = _parse(t["detected_at"])
        if dt:
            key = dt.strftime("%Y-%m-%d")
            if key in per_day:
                per_day[key][t["severity"]] += 1
    daily = [{"date": d, "total": sum(c.values()), **{s: c.get(s, 0) for s in ("critical", "high", "medium", "low", "info")}}
             for d, c in per_day.items()]

    # ---- time-to metrics (minutes)
    mttd, mtta, mttc, mttr = [], [], [], []
    for t in threats:
        d, c = _parse(t["detected_at"]), _parse(t["created_at"])
        if d and c and c >= d:
            mttd.append(_mins(c - d))  # source event -> platform detection
    for i in incidents:
        first, created = _parse(i["first_seen_at"]), _parse(i["created_at"])
        if first and created and created >= first:
            mtta.append(_mins(created - first))
        contained, resolved = _parse(i.get("contained_at")), _parse(i.get("resolved_at"))
        if first and contained and contained >= first:
            mttc.append(_mins(contained - first))
        if first and resolved and resolved >= first:
            mttr.append(_mins(resolved - first))

    def stat(values: list[float]) -> dict[str, Any]:
        return {"count": len(values), "median_minutes": round(median(values), 1) if values else None,
                "mean_minutes": round(sum(values) / len(values), 1) if values else None}

    # ---- top lists
    ips = Counter(ip for t in threats for ip in (t.get("source_ips") or []))
    techniques = Counter(x for t in threats for x in (t.get("mitre_techniques") or []))
    tactics = Counter(x for t in threats for x in (t.get("mitre_tactics") or []))

    # ---- agents
    by_agent: dict[str, dict[str, Any]] = {}
    for r in runs:
        a = by_agent.setdefault(r["agent_key"], {"agent_key": r["agent_key"], "runs": 0, "failed": 0, "latency": [], "tokens": 0})
        a["runs"] += 1
        a["failed"] += 1 if r["status"] == "failed" else 0
        if r.get("latency_ms"):
            a["latency"].append(r["latency_ms"])
        a["tokens"] += int(r.get("total_tokens") or 0)
    agents = [
        {"agent_key": a["agent_key"], "runs": a["runs"], "failed": a["failed"],
         "success_rate": round(100 * (a["runs"] - a["failed"]) / a["runs"], 1),
         "avg_latency_ms": round(sum(a["latency"]) / len(a["latency"])) if a["latency"] else None,
         "tokens": a["tokens"]}
        for a in sorted(by_agent.values(), key=lambda x: -x["runs"])
    ]

    # ---- approvals funnel
    funnel = Counter()
    for a in approvals:
        funnel[a["status"]] += 1
        if a.get("execution_status"):
            funnel[a["execution_status"]] += 1

    raw_events = sum(int(t.get("event_count") or 1) for t in threats)
    open_rows = open_incidents.data or []
    return {
        "window_days": days,
        "truncated": len(threats) >= _ROW_CAP or len(incidents) >= _ROW_CAP,
        "totals": {
            "threats": len(threats),
            "raw_events_folded": raw_events,
            "duplicates_suppressed": max(0, raw_events - len(threats)),
            "incidents_created": len(incidents),
            "open_incidents": open_incidents.count or 0,
            "unassigned_open_incidents": sum(1 for r in open_rows if not r.get("assigned_to")),
            "critical_open_incidents": sum(1 for r in open_rows if r["severity"] == "critical"),
        },
        "severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
        "daily": daily,
        "mttd": stat(mttd), "mtta": stat(mtta), "mttc": stat(mttc), "mttr": stat(mttr),
        "top_source_ips": [{"ip": k, "threats": v} for k, v in ips.most_common(8)],
        "top_techniques": [{"technique": k, "threats": v} for k, v in techniques.most_common(8)],
        "tactics": [{"tactic": k, "threats": v} for k, v in tactics.most_common()],
        "agents": agents,
        "approvals": {k: funnel.get(k, 0) for k in ("pending", "approved", "rejected", "executed", "failed")},
    }
