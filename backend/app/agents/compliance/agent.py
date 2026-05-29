from __future__ import annotations

from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.compliance.schemas import (
    ComplianceInput,
    ComplianceOutput,
)
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class ComplianceAgent(BaseAgent):
    """Produces regulatory compliance assessments for incidents."""

    agent_key = "compliance"
    json_mode = True

    def _fetch_incident(
        self, *, organization_id: str, short_id: str
    ) -> dict[str, Any] | None:
        client = get_supabase_admin()
        result = (
            client.table("incidents")
            .select(
                "id, short_id, title, description, severity, status, "
                "confidence, kill_chain, threat_count, "
                "first_seen_at, last_seen_at, affected_asset_ids"
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
                "short_id, title, severity, source_ips, target_ips, "
                "affected_users, tags, iocs"
            )
            .eq("organization_id", organization_id)
            .eq("incident_id", incident_id)
            .limit(30)
            .execute()
        )
        return result.data or []

    def _fetch_assets(
        self, *, organization_id: str, asset_ids: list[str]
    ) -> list[dict[str, Any]]:
        if not asset_ids:
            return []
        client = get_supabase_admin()
        result = (
            client.table("assets")
            .select("id, name, asset_type, environment, criticality, tags")
            .eq("organization_id", organization_id)
            .in_("id", asset_ids)
            .execute()
        )
        return result.data or []


    def build_user_prompt(self, agent_input: AgentInput) -> str:
        params = ComplianceInput.model_validate(agent_input.payload)
        org_id = str(agent_input.organization_id)

        incident = self._fetch_incident(
            organization_id=org_id, short_id=params.incident_short_id
        )
        if not incident:
            return (
                f"Incident '{params.incident_short_id}' was not found. "
                f"Return a JSON object with empty `reports`, "
                f"`overall_compliance_risk`='low', and explain in "
                f"executive_summary that the incident does not exist."
            )

        threats = self._fetch_threats(
            organization_id=org_id, incident_id=incident["id"]
        )
        asset_ids = incident.get("affected_asset_ids") or []
        assets = self._fetch_assets(organization_id=org_id, asset_ids=asset_ids)

        lines: list[str] = [
            "INCIDENT TO ASSESS FOR COMPLIANCE:",
            f"  short_id:    {incident.get('short_id')}",
            f"  title:       {incident.get('title')}",
            f"  severity:    {incident.get('severity')}",
            f"  confidence:  {incident.get('confidence')}",
            f"  detected:    {incident.get('first_seen_at', '?')}",
            f"  description: {(incident.get('description') or '')[:400]}",
        ]

        if assets:
            lines.append("")
            lines.append("AFFECTED ASSETS:")
            for a in assets:
                lines.append(
                    f"- {a.get('name')} | type={a.get('asset_type')} | "
                    f"env={a.get('environment')} | criticality={a.get('criticality')}"
                )
                if a.get("tags"):
                    lines.append(f"    tags: {a['tags']}")

        if threats:
            lines.append("")
            lines.append("ASSOCIATED THREATS (truncated):")
            for t in threats[:10]:
                lines.append(
                    f"- [{t['short_id']}] {t.get('severity')} | "
                    f"{t.get('title', '')[:120]}"
                )
                if t.get("affected_users"):
                    lines.append(f"    users: {t['affected_users'][:3]}")
                if t.get("tags"):
                    lines.append(f"    tags: {t['tags'][:5]}")

        regs_str = ", ".join(params.regulations)

        lines.extend(
            [
                "",
                "TASK:",
                f"Produce a regulatory compliance assessment covering: {regs_str}.",
                "For each regulation, decide whether it likely applies based on the data,",
                "assets, and severity involved. Use ONLY the data above — be precise.",
                "",
                "Respond with a single JSON object:",
                "{",
                f'  "incident_short_id":        "{incident.get("short_id")}",',
                '  "overall_compliance_risk":  one of "low","medium","high","critical",',
                '  "executive_summary":        1 paragraph for legal/leadership,',
                '  "applicable_regulations":   list of regulations that apply,',
                '  "mandatory_deadlines":      list of deadline reminders,',
                '  "reports": [',
                "    {",
                '      "regulation":                  "GDPR" | "HIPAA" | "PCI-DSS" | "SOC2" | "ISO27001",',
                '      "applies":                     true | false,',
                '      "reason":                      1-2 sentences,',
                '      "notification_required":       true | false,',
                '      "notification_deadline_hours": integer or null,',
                '      "affected_data_categories":    list like ["personal_data","payment_data"],',
                '      "estimated_affected_records":  integer or null,',
                '      "risk_to_data_subjects":       "low" | "medium" | "high" | "severe" | "unknown",',
                '      "mitigations_in_place":        list of strings,',
                '      "required_actions":            list of strings,',
                '      "notification_template":       short draft (<=500 chars) or null',
                "    }",
                "  ],",
                '  "recommended_next_steps":   list of strings',
                "}",
                "",
                "GUIDELINES:",
                "- GDPR applies if the org likely handles EU personal data (assume yes for B2B SaaS).",
                "- HIPAA applies only if healthcare/PHI is involved (look at asset tags).",
                "- PCI-DSS applies only if payment card data is involved.",
                "- SOC 2 and ISO 27001 apply to most security incidents at SaaS companies.",
                "- Be conservative — don't claim applicability without basis from the data.",
                "- Always include the affected_data_categories array.",
                "- Keep notification_template under 500 characters.",
                "- Total response should be under 2000 words.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        ComplianceOutput.model_validate(parsed)


__all__ = ["ComplianceAgent"]