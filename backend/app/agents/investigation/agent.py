from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from app.agents.base import AgentInput, BaseAgent
from app.agents.investigation.schemas import (
    InvestigationInput,
    InvestigationOutput,
    ThreatGroup,
)
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


_SEVERITY_RANK = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


class InvestigationAgent(BaseAgent):
    """Looks at recent threats and groups related ones into incidents."""

    agent_key = "investigation"
    json_mode = True


    def _fetch_recent_threats(
        self,
        *,
        organization_id: str,
        lookback_hours: int,
        min_severity: str,
        max_threats: int,
    ) -> list[dict[str, Any]]:
        """Pull recent open threats for the org from the database."""
        client = get_supabase_admin()
        since = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
        min_rank = _SEVERITY_RANK.get(min_severity.lower(), 2)
        valid_severities = [s for s, r in _SEVERITY_RANK.items() if r >= min_rank]

        result = (
            client.table("threats")
            .select(
                "id, short_id, title, description, severity, confidence, "
                "risk_score, status, mitre_tactics, mitre_techniques, "
                "source_ips, target_ips, affected_users, tags, "
                "detected_at, incident_id"
            )
            .eq("organization_id", organization_id)
            .gte("detected_at", since)
            .in_("status", ["open", "investigating"])
            .in_("severity", valid_severities)
            .order("detected_at", desc=True)
            .limit(max_threats)
            .execute()
        )

        threats = result.data or []
        log.info(
            "investigation_threats_fetched",
            count=len(threats),
            lookback_hours=lookback_hours,
            min_severity=min_severity,
        )
        return threats

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        """Build the prompt with the recent-threats window inline."""
        params = InvestigationInput.model_validate(agent_input.payload)
        threats = self._fetch_recent_threats(
            organization_id=str(agent_input.organization_id),
            lookback_hours=params.lookback_hours,
            min_severity=params.min_severity,
            max_threats=params.max_threats,
        )
        # Stash for later use by the endpoint
        self._last_threats = threats

        if not threats:
            return (
                "There are no open threats in the requested window. "
                "Return a JSON object with empty `groups`, empty "
                "`unrelated_threat_short_ids`, and a `summary` explaining "
                "that no correlation work was needed."
            )

        lines: list[str] = [
            f"You are analyzing {len(threats)} open threats from the last "
            f"{params.lookback_hours} hours in this organization's environment.",
            "",
            "THREATS:",
        ]

        for t in threats:
            ips = (t.get("source_ips") or [])[:3]
            users = (t.get("affected_users") or [])[:3]
            mitre_techs = (t.get("mitre_techniques") or [])[:5]
            lines.append(
                f"- [{t['short_id']}] severity={t.get('severity')} "
                f"confidence={t.get('confidence')}  "
                f"detected={t.get('detected_at', '?')[:19]}"
            )
            lines.append(f"    title: {t.get('title', '')[:200]}")
            if t.get("description"):
                lines.append(f"    desc:  {t['description'][:200]}")
            if ips:
                lines.append(f"    source_ips: {ips}")
            if users:
                lines.append(f"    users: {users}")
            if mitre_techs:
                lines.append(f"    mitre: {mitre_techs}")

        lines.extend(
            [
                "",
                "TASK:",
                "Identify clusters of threats that look like parts of the SAME attack story.",
                "Threats can be linked by: shared source_ip, shared target_user, similar timing,",
                "MITRE tactic chains (recon → exploit → persistence), or behavioral patterns.",
                "",
                "Respond with a single JSON object:",
                "{",
                '  "groups": [',
                "    {",
                '      "title":               short incident title (<=200 chars),',
                '      "summary":             2-3 sentence story of the attack,',
                '      "severity":            one of "info","low","medium","high","critical" (highest of members),',
                '      "confidence":          0-100 how sure you are these are related,',
                '      "threat_short_ids":    array of short_ids that belong to this group,',
                '      "kill_chain_phase":    one of the Lockheed phases or null,',
                '      "attribution_hint":    free-form guess like "scripted scanner" or null,',
                '      "reasoning":           why you grouped these',
                "    }",
                "  ],",
                '  "unrelated_threat_short_ids": short_ids that don\'t fit any group,',
                '  "summary":                    1-2 sentence overall takeaway',
                "}",
                "",
                "GUIDELINES:",
                "- A group needs >=2 threats. Singletons go to unrelated_threat_short_ids.",
                "- Only use short_ids that appear in the THREATS list above.",
                "- Be conservative — better to leave a threat unrelated than to invent links.",
                "- If everything is unrelated, return empty `groups` and explain in summary.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        """Reject responses that don't conform to InvestigationOutput."""
        InvestigationOutput.model_validate(parsed)

    def create_incidents_from_output(
        self,
        *,
        organization_id: UUID | str,
        verdict: InvestigationOutput,
        agent_run_id: str,
    ) -> list[dict[str, str]]:
        """For each group in the verdict, create an incident row and
        link the member threats. Returns list of created incident metadata."""
        if not verdict.groups:
            return []

        client = get_supabase_admin()
        org_id = str(organization_id)
        created: list[dict[str, str]] = []

        # Build short_id → id lookup for the threats we just analyzed
        threats_seen = getattr(self, "_last_threats", []) or []
        short_to_id = {t["short_id"]: t["id"] for t in threats_seen}

        for group in verdict.groups:
            member_ids = [short_to_id[s] for s in group.threat_short_ids if s in short_to_id]
            if len(member_ids) < 2:
                # Group must have at least 2 valid threat refs; skip otherwise
                continue

# kill_chain is an ARRAY in the schema, not a string
            kill_chain_array = (
                [group.kill_chain_phase] if group.kill_chain_phase else []
            )

            incident_insert = (
                client.table("incidents")
                .insert(
                    {
                        "organization_id": org_id,
                        "title": group.title,
                        "description": group.summary,
                        "severity": group.severity.value,
                        "status": "open",
                        "confidence": group.confidence,
                        "kill_chain": kill_chain_array,
                        "attribution": (
                            {"hint": group.attribution_hint}
                            if group.attribution_hint
                            else {}
                        ),
                        "ai_summary": {
                            "investigation_run_id": agent_run_id,
                            "summary": group.summary,
                            "reasoning": group.reasoning,
                        },
                        "threat_count": len(member_ids),
                    }
                )
                .execute()
            )
            incident_row = incident_insert.data[0]
            incident_id = incident_row["id"]

            # Link the threats to the new incident
            client.table("threats").update({"incident_id": incident_id}).in_(
                "id", member_ids
            ).execute()

            log.info(
                "incident_created",
                incident_id=incident_id,
                short_id=incident_row.get("short_id"),
                threat_count=len(member_ids),
                severity=group.severity.value,
            )
            created.append(
                {
                    "incident_id": incident_id,
                    "short_id": incident_row.get("short_id"),
                    "title": group.title,
                    "threat_count": str(len(member_ids)),
                }
            )

        return created


__all__ = ["InvestigationAgent"]