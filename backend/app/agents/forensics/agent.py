from __future__ import annotations

from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.forensics.schemas import (
    ForensicsInput,
    ForensicsOutput,
)
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class ForensicsAgent(BaseAgent):
    """Reconstructs chronological attack timelines from incidents."""

    agent_key = "forensics"
    json_mode = True

    def _fetch_incident(
        self, *, organization_id: str, short_id: str
    ) -> dict[str, Any] | None:
        client = get_supabase_admin()
        result = (
            client.table("incidents")
            .select(
                "id, short_id, title, description, severity, status, "
                "confidence, kill_chain, attribution, threat_count, "
                "first_seen_at, last_seen_at"
            )
            .eq("organization_id", organization_id)
            .eq("short_id", short_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    def _fetch_threats(
        self, *, organization_id: str, incident_id: str
    ) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        result = (
            client.table("threats")
            .select(
                "short_id, title, description, severity, confidence, "
                "detected_at, source_ips, target_ips, affected_users, "
                "mitre_tactics, mitre_techniques, iocs, tags, ai_analysis"
            )
            .eq("organization_id", organization_id)
            .eq("incident_id", incident_id)
            .order("detected_at", desc=False)
            .limit(100)
            .execute()
        )
        return result.data or []

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        params = ForensicsInput.model_validate(agent_input.payload)
        org_id = str(agent_input.organization_id)

        incident = self._fetch_incident(
            organization_id=org_id, short_id=params.incident_short_id
        )
        if not incident:
            return (
                f"Incident '{params.incident_short_id}' was not found. "
                f"Return a JSON object with empty arrays everywhere, "
                f"overall_severity='info', and explain in executive_summary "
                f"that the incident does not exist."
            )

        threats = self._fetch_threats(
            organization_id=org_id, incident_id=incident["id"]
        )

        lines: list[str] = [
            "INCIDENT TO RECONSTRUCT:",
            f"  short_id:     {incident.get('short_id')}",
            f"  title:        {incident.get('title')}",
            f"  severity:     {incident.get('severity')}",
            f"  first_seen:   {incident.get('first_seen_at') or '?'}",
            f"  last_seen:    {incident.get('last_seen_at') or '?'}",
            f"  threats:      {incident.get('threat_count') or 0}",
            f"  description:  {(incident.get('description') or '')[:500]}",
        ]

        if not threats:
            lines.append("")
            lines.append("ASSOCIATED THREATS: (none linked yet)")
        else:
            lines.append("")
            lines.append("ASSOCIATED THREATS (CHRONOLOGICAL):")
            for t in threats:
                ips = (t.get("source_ips") or [])[:3]
                users = (t.get("affected_users") or [])[:3]
                mitre_techs = (t.get("mitre_techniques") or [])[:5]
                lines.append(
                    f"- [{t['short_id']}] {t.get('detected_at', '?')[:19]}  "
                    f"severity={t.get('severity')} confidence={t.get('confidence')}"
                )
                lines.append(f"    title: {t.get('title', '')[:200]}")
                if t.get("description"):
                    lines.append(f"    desc:  {t['description'][:300]}")
                if ips:
                    lines.append(f"    source_ips: {ips}")
                if users:
                    lines.append(f"    users: {users}")
                if mitre_techs:
                    lines.append(f"    mitre: {mitre_techs}")
                iocs = t.get("iocs") or {}
                if iocs:
                    lines.append(f"    iocs: {iocs}")

        lines.extend(
            [
                "",
                "TASK:",
                "You are a forensic investigator. Reconstruct this incident as a chronological",
                "story suitable for legal review. Use ONLY the data above — do not invent details.",
                "",
                "Respond with a single JSON object:",
                "{",
                f'  "incident_short_id":  "{incident.get("short_id")}",',
                '  "overall_severity":   one of "info","low","medium","high","critical",',
                '  "executive_summary":  1 paragraph for non-technical readers,',
                '  "attack_narrative":   2-3 short paragraphs, investigator-style,',
                '  "timeline": [',
                "    {",
                '      "timestamp":         ISO-8601 (copy from threat.detected_at),',
                '      "threat_short_id":   the source threat short_id,',
                '      "phase":             one of the MITRE-style kill-chain phases,',
                '      "actor":             who/what (IP, user, process) or null,',
                '      "target":            host/asset/user targeted or null,',
                '      "description":      what happened in this step,',
                '      "artifacts":        list of concrete artifacts (hashes, IPs, paths)',
                "    }",
                "  ],",
                '  "key_artifacts":            top 5-10 most important IOCs / files / accounts,',
                '  "evidence_recommendations": list of things to preserve (e.g. "Memory dump of prod-web-01"),',
                '  "affected_assets":          list of asset names involved,',
                '  "affected_users":           list of user accounts involved',
                "}",
                "",
                "GUIDELINES:",
                "- Be factual. If something is unknown, leave it null or empty.",
                "- The timeline MUST be in chronological order.",
                "- Each timeline event maps to exactly one threat_short_id from above.",
                "- Use MITRE-style phase names where possible.",
                "- The narrative should read like a forensic report, not a chat message.",
                "- Keep the narrative concise — 2-3 short paragraphs maximum.",
                "- Keep total response under 1500 words. Be precise, not verbose.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        ForensicsOutput.model_validate(parsed)


__all__ = ["ForensicsAgent"]