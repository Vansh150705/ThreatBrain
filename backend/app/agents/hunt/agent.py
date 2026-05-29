from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.hunt.schemas import HuntInput, HuntOutput
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class HuntAgent(BaseAgent):
    """Generates proactive threat hunting hypotheses."""

    agent_key = "hunt"
    json_mode = True

    def _fetch_recent_threats(
        self, *, organization_id: str, lookback_hours: int
    ) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
        result = (
            client.table("threats")
            .select(
                "short_id, title, severity, status, mitre_tactics, "
                "mitre_techniques, source_ips, affected_users, tags, "
                "detected_at"
            )
            .eq("organization_id", organization_id)
            .gte("detected_at", since)
            .order("detected_at", desc=True)
            .limit(40)
            .execute()
        )
        return result.data or []

    def _fetch_recent_iocs(
        self, *, organization_id: str, lookback_hours: int
    ) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
        result = (
            client.table("iocs")
            .select(
                "short_id, ioc_type, value, reputation, "
                "threat_score, geo_country, tags, source_feeds, updated_at"
            )
            .eq("organization_id", organization_id)
            .gte("updated_at", since)
            .order("threat_score", desc=True)
            .limit(40)
            .execute()
        )
        return result.data or []

    def _fetch_assets(self, *, organization_id: str) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        result = (
            client.table("assets")
            .select(
                "id, name, asset_type, environment, criticality, tags"
            )
            .eq("organization_id", organization_id)
            .eq("status", "active")
            .limit(30)
            .execute()
        )
        return result.data or []

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        params = HuntInput.model_validate(agent_input.payload)
        org_id = str(agent_input.organization_id)

        threats = self._fetch_recent_threats(
            organization_id=org_id, lookback_hours=params.lookback_hours
        )
        iocs = self._fetch_recent_iocs(
            organization_id=org_id, lookback_hours=params.lookback_hours
        )
        assets = self._fetch_assets(organization_id=org_id)

        # Stash counts for the response wrapper
        self._counts = {
            "threats": len(threats),
            "iocs": len(iocs),
            "assets": len(assets),
        }

        lines: list[str] = [
            "PROACTIVE THREAT HUNT — CONTEXT:",
            f"  lookback_window: {params.lookback_hours} hours",
            f"  threats_in_window: {len(threats)}",
            f"  iocs_in_window:    {len(iocs)}",
            f"  active_assets:     {len(assets)}",
        ]
        if params.focus_areas:
            lines.append(f"  focus_areas:       {params.focus_areas}")

        if threats:
            lines.append("")
            lines.append("RECENT THREATS:")
            for t in threats[:15]:
                techs = (t.get("mitre_techniques") or [])[:3]
                tags = (t.get("tags") or [])[:3]
                lines.append(
                    f"- [{t['short_id']}] {t.get('severity')} | "
                    f"{t.get('title', '')[:140]}"
                )
                if techs:
                    lines.append(f"    mitre: {techs}")
                if tags:
                    lines.append(f"    tags:  {tags}")

        if iocs:
            lines.append("")
            lines.append("RECENT/HIGH-RISK IOCs:")
            for i in iocs[:15]:
                lines.append(
                    f"- [{i['short_id']}] type={i.get('ioc_type')} "
                    f"reputation={i.get('reputation')} "
                    f"score={i.get('threat_score')} "
                    f"country={i.get('geo_country')} "
                    f"value={i.get('value')[:50]}"
                )

        if assets:
            lines.append("")
            lines.append("ACTIVE ASSETS:")
            for a in assets[:15]:
                lines.append(
                    f"- {a.get('name')} | type={a.get('asset_type')} | "
                    f"env={a.get('environment')} | criticality={a.get('criticality')}"
                )

        focus_hint = ""
        if params.focus_areas:
            focus_hint = (
                f"\nFocus your hypotheses on these MITRE-style areas: "
                f"{params.focus_areas}."
            )

        lines.extend(
            [
                "",
                "TASK:",
                f"You are a senior threat hunter. Generate up to {params.max_hypotheses} "
                "testable hunting hypotheses about hidden adversaries that might be present"
                " given the patterns above. Each hypothesis MUST be specific, testable, "
                "and grounded in the data shown — do not invent IOCs or threats not present."
                + focus_hint,
                "",
                "Respond with a single JSON object:",
                "{",
                '  "summary":            1-2 sentence overall hunt strategy,',
                '  "hypotheses": [',
                "    {",
                '      "title":              short headline (<=120 chars),',
                '      "hypothesis":         the full hypothesis statement,',
                '      "likelihood":         "low" | "medium" | "high",',
                '      "confidence":         integer 0-100,',
                '      "mitre_techniques":   list of MITRE technique IDs,',
                '      "suggested_query":    a SQL-like or log-search query the analyst can run,',
                '      "expected_evidence":  list of concrete signals that would confirm it,',
                '      "rationale":          why this hypothesis follows from the data above',
                "    }",
                "  ],",
                '  "threats_considered": ' + str(len(threats)) + ",",
                '  "iocs_considered":    ' + str(len(iocs)) + ",",
                '  "assets_considered":  ' + str(len(assets)),
                "}",
                "",
                "GUIDELINES:",
                "- Prefer hypotheses about persistence, lateral movement, and dormant backdoors.",
                "- The suggested_query MUST be specific (e.g. 'SELECT * FROM events WHERE ...')",
                "- Each hypothesis must have at least 1 MITRE technique.",
                "- Be conservative — better fewer strong hypotheses than many weak ones.",
                "- Keep total response under 2000 words.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        HuntOutput.model_validate(parsed)


__all__ = ["HuntAgent"]