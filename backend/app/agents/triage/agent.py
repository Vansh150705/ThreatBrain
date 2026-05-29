from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from app.agents.base import AgentInput, AgentRunResult, BaseAgent
from app.agents.triage.schemas import TriageInput, TriageOutput
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class TriageAgent(BaseAgent):
    """The first responder. Classifies events into threats."""

    agent_key = "triage"
    json_mode = True


    def build_user_prompt(self, agent_input: AgentInput) -> str:

        event = TriageInput.model_validate(agent_input.payload)

        # Build a clean, formatted event description
        lines: list[str] = ["SECURITY EVENT TO CLASSIFY:", ""]

        lines.append(f"TITLE:       {event.title}")
        if event.description:
            lines.append(f"DESCRIPTION: {event.description}")
        lines.append(f"SOURCE:      {event.source}")
        lines.append(f"EVENT TYPE:  {event.event_type}")

        # Network
        net_parts = []
        if event.source_ip:
            sp = f":{event.source_port}" if event.source_port else ""
            net_parts.append(f"src={event.source_ip}{sp}")
        if event.destination_ip:
            dp = f":{event.destination_port}" if event.destination_port else ""
            net_parts.append(f"dst={event.destination_ip}{dp}")
        if net_parts:
            lines.append(f"NETWORK:     {' '.join(net_parts)}")

        # Identity / process / file
        if event.username:
            lines.append(f"USER:        {event.username}")
        if event.process_name:
            lines.append(f"PROCESS:     {event.process_name}")
        if event.command_line:
            preview = event.command_line[:500]
            lines.append(f"COMMAND:     {preview}")
        if event.file_hash:
            lines.append(f"FILE HASH:   {event.file_hash}")

        # Asset
        asset_parts = []
        if event.asset_name:
            asset_parts.append(event.asset_name)
        if event.asset_type:
            asset_parts.append(f"({event.asset_type})")
        if event.asset_environment:
            asset_parts.append(f"[{event.asset_environment}]")
        if event.asset_criticality:
            asset_parts.append(f"criticality={event.asset_criticality}")
        if asset_parts:
            lines.append(f"ASSET:       {' '.join(asset_parts)}")

        if event.raw_data:
            lines.append("")
            lines.append("RAW DATA:")
            lines.append(json.dumps(event.raw_data, indent=2)[:2000])

        lines.extend(
            [
                "",
                "TASK:",
                "Classify this event. Respond with a single JSON object containing exactly these fields:",
                "",
                "{",
                '  "severity":         one of "info", "low", "medium", "high", "critical",',
                '  "confidence":       integer 0-100, how sure you are this is real,',
                '  "title":            short one-line summary (<= 200 chars),',
                '  "description":      2-3 sentence human-readable explanation,',
                '  "reasoning":        why you assigned this severity, citing evidence,',
                '  "mitre_tactics":    array of MITRE ATT&CK tactic IDs, e.g. ["TA0001","TA0006"],',
                '  "mitre_techniques": array of technique IDs, e.g. ["T1110","T1110.001"],',
                '  "tags":             array of short labels like ["brute-force","ssh"],',
                '  "promote_to_threat": true if this warrants a threat record, else false',
                "}",
                "",
                "GUIDELINES:",
                "- Weight severity by asset criticality (crown_jewel >> medium).",
                "- Be conservative with 'critical'; reserve for confirmed-active attacks.",
                "- If asset_criticality is 'crown_jewel' and severity >= 'medium', set promote_to_threat=true.",
                "- If you see brute-force patterns (>20 failed auths from one IP), promote_to_threat=true.",
                "- For routine info/low events with no IOCs, promote_to_threat=false.",
                "- Always include at least one MITRE tactic and technique if applicable.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        """Reject responses that don't conform to TriageOutput."""
        TriageOutput.model_validate(parsed)

    def promote_to_threat(
        self,
        *,
        organization_id: UUID | str,
        triage_input: TriageInput,
        triage_output: TriageOutput,
        agent_run_id: str,
        primary_asset_id: str | None = None,
    ) -> str:
        """Insert a row into public.threats based on the agent's verdict.

        Returns the new threat's UUID.
        """
        client = get_supabase_admin()

        source_ips = [triage_input.source_ip] if triage_input.source_ip else []
        target_ips = [triage_input.destination_ip] if triage_input.destination_ip else []
        affected_users = [triage_input.username] if triage_input.username else []

        # Build an IOC bundle the Threat Intel agent will enrich later
        iocs: dict[str, Any] = {}
        if triage_input.source_ip:
            iocs["ips"] = [triage_input.source_ip]
        if triage_input.file_hash:
            iocs["hashes"] = [triage_input.file_hash]

        # risk_score: weighted blend of severity tier * confidence
        severity_weight = {
            "info": 5,
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 95,
        }[triage_output.severity.value]
        risk_score = int(severity_weight * (triage_output.confidence / 100))

        result = (
            client.table("threats")
            .insert(
                {
                    "organization_id": str(organization_id),
                    "primary_asset_id": primary_asset_id,
                    "title": triage_output.title,
                    "description": triage_output.description,
                    "severity": triage_output.severity.value,
                    "status": "open",
                    "confidence": triage_output.confidence,
                    "risk_score": risk_score,
                    "mitre_tactics": triage_output.mitre_tactics,
                    "mitre_techniques": triage_output.mitre_techniques,
                    "source_ips": source_ips,
                    "target_ips": target_ips,
                    "affected_users": affected_users,
                    "iocs": iocs,
                    "ai_analysis": {
                        "triage_run_id": agent_run_id,
                        "reasoning": triage_output.reasoning,
                    },
                    "tags": triage_output.tags,
                }
            )
            .execute()
        )

        threat_id = result.data[0]["id"]
        threat_short_id = result.data[0]["short_id"]
        log.info(
            "threat_promoted",
            threat_id=threat_id,
            threat_short_id=threat_short_id,
            severity=triage_output.severity.value,
            confidence=triage_output.confidence,
            risk_score=risk_score,
        )
        return threat_id


__all__ = ["TriageAgent"]