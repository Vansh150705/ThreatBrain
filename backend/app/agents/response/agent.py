from __future__ import annotations

from typing import Any
from uuid import UUID

from app.agents.base import AgentInput, BaseAgent
from app.agents.response.schemas import (
    ActionRecommendation,
    ResponseInput,
    ResponseOutput,
)
from app.core.logging import get_logger
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class ResponseAgent(BaseAgent):
    """Selects and executes/recommends playbooks for an incident."""

    agent_key = "response"
    json_mode = True

    def _fetch_incident(
        self, *, organization_id: str, short_id: str
    ) -> dict[str, Any] | None:
        client = get_supabase_admin()
        result = (
            client.table("incidents")
            .select(
                "id, short_id, title, description, severity, status, "
                "confidence, kill_chain, attribution, threat_count"
            )
            .eq("organization_id", organization_id)
            .eq("short_id", short_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    def _fetch_threats_for_incident(
        self, *, organization_id: str, incident_id: str
    ) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        result = (
            client.table("threats")
            .select(
                "short_id, title, severity, source_ips, target_ips, "
                "affected_users, mitre_techniques, tags"
            )
            .eq("organization_id", organization_id)
            .eq("incident_id", incident_id)
            .limit(20)
            .execute()
        )
        return result.data or []

    def _fetch_playbooks(self, *, organization_id: str) -> list[dict[str, Any]]:
        client = get_supabase_admin()
        result = (
            client.table("playbooks")
            .select(
                "id, name, description, category, auto_execute, "
                "approval_required, max_severity_auto, min_confidence, "
                "steps, mitre_techniques, enabled"
            )
            .eq("organization_id", organization_id)
            .eq("enabled", True)
            .execute()
        )
        return result.data or []

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        params = ResponseInput.model_validate(agent_input.payload)
        org_id = str(agent_input.organization_id)

        incident = self._fetch_incident(
            organization_id=org_id, short_id=params.incident_short_id
        )
        if not incident:
            self._last_incident = None
            self._last_threats = []
            self._last_playbooks = []
            return (
                f"Incident '{params.incident_short_id}' was not found. "
                f"Return a JSON object with empty `actions`, "
                f"`overall_severity`='info', and a summary noting that nothing was done."
            )

        threats = self._fetch_threats_for_incident(
            organization_id=org_id, incident_id=incident["id"]
        )
        playbooks = self._fetch_playbooks(organization_id=org_id)

        # Stash for use after LLM returns
        self._last_incident = incident
        self._last_threats = threats
        self._last_playbooks = playbooks

        lines: list[str] = [
            "INCIDENT TO RESPOND TO:",
            f"  short_id:    {incident.get('short_id')}",
            f"  title:       {incident.get('title')}",
            f"  severity:    {incident.get('severity')}",
            f"  confidence:  {incident.get('confidence')}",
            f"  description: {(incident.get('description') or '')[:400]}",
        ]

        if threats:
            lines.append("")
            lines.append("ASSOCIATED THREATS:")
            for t in threats[:10]:
                ips = (t.get("source_ips") or [])[:2]
                users = (t.get("affected_users") or [])[:2]
                lines.append(
                    f"- [{t['short_id']}] {t.get('severity')} | "
                    f"{t.get('title', '')[:120]}"
                )
                if ips:
                    lines.append(f"    source_ips: {ips}")
                if users:
                    lines.append(f"    users: {users}")

        if playbooks:
            lines.append("")
            lines.append("AVAILABLE PLAYBOOKS:")
            for p in playbooks:
                # Derive a primary action_type from the first step if present
                steps_raw = p.get("steps") or []
                first_step_action = ""
                if isinstance(steps_raw, list) and steps_raw:
                    first = steps_raw[0]
                    if isinstance(first, dict):
                        first_step_action = first.get("action") or first.get("type") or ""

                lines.append(
                    f"- name='{p['name']}' | category={p.get('category')} | "
                    f"auto_execute={p.get('auto_execute')} | "
                    f"approval_required={p.get('approval_required')} | "
                    f"max_severity_auto={p.get('max_severity_auto')}"
                )
                if p.get("description"):
                    lines.append(f"    desc:  {p['description'][:200]}")
                if first_step_action:
                    lines.append(f"    primary_action: {first_step_action}")
        else:
            lines.append("")
            lines.append("AVAILABLE PLAYBOOKS: (none configured)")

        lines.extend(
            [
                "",
                "TASK:",
                "Choose which playbooks to apply to this incident and pick the target for each.",
                "Respond with a single JSON object:",
                "{",
                f'  "incident_short_id":  "{incident.get("short_id")}",',
                '  "overall_severity":   one of "info","low","medium","high","critical",',
                '  "summary":            1-2 sentence action plan,',
                '  "actions": [',
                "    {",
                '      "playbook_name":  exact name from AVAILABLE PLAYBOOKS,',
                '      "action_type":    block_ip|disable_user|isolate_host|notify|quarantine_email|revoke_token|other,',
                '      "target":         the IP / user / host this action targets,',
                '      "priority":       1-10 (1 = highest),',
                '      "rationale":      why this action makes sense',
                "    }",
                "  ],",
                '  "skipped_count":      0,',
                '  "executed_count":     0,',
                '  "simulated_count":    0,',
                '  "recommended_count":  0',
                "}",
                "",
                "GUIDELINES:",
                "- Only choose playbooks that appear in AVAILABLE PLAYBOOKS.",
                "- Pick the right target from THREATS (IPs from source_ips, users from affected_users).",
                "- Don't repeat the same playbook for the same target.",
                "- Set all counts to 0 — the system fills them in after applying.",
                "- If no playbook fits, return empty `actions` and explain in summary.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        ResponseOutput.model_validate(parsed)

    def apply_actions(
        self,
        *,
        organization_id: UUID | str,
        verdict: ResponseOutput,
        agent_run_id: str,
        dry_run: bool,
        execute_auto_playbooks: bool,
    ) -> ResponseOutput:

        if self._last_incident is None or not verdict.actions:
            return verdict

        client = get_supabase_admin()
        org_id = str(organization_id)
        incident = self._last_incident
        playbooks_by_name = {p["name"]: p for p in (self._last_playbooks or [])}

        executed = 0
        simulated = 0
        recommended = 0
        skipped = 0

        for action in verdict.actions:
            playbook = playbooks_by_name.get(action.playbook_name)
            if playbook is None:
                action.status = "skipped"
                skipped += 1
                log.warning(
                    "response_playbook_not_found",
                    playbook_name=action.playbook_name,
                )
                continue

            # Decide outcome based on flags + playbook permissions
            if dry_run:
                action.status = "simulated"
                simulated += 1
                outcome = "simulated"
            elif execute_auto_playbooks and playbook.get("auto_execute"):
                action.status = "executed"
                executed += 1
                outcome = "executed"
            else:
                action.status = "recommended"
                recommended += 1
                outcome = "recommended"

            # Anything not auto-executed lands in the human approval queue.
            # Wrapped separately so a missing table never breaks the run.
            if outcome in ("simulated", "recommended"):
                try:
                    client.table("playbook_approvals").insert(
                        {
                            "organization_id": org_id,
                            "incident_id": incident["id"],
                            "incident_short_id": incident.get("short_id"),
                            "incident_title": incident.get("title"),
                            "playbook_name": action.playbook_name,
                            "action_type": action.action_type,
                            "target": action.target,
                            "priority": action.priority,
                            "rationale": action.rationale[:500],
                            "requested_by": agent_run_id,
                        }
                    ).execute()
                except Exception:
                    log.exception("playbook_approval_insert_failed")

            # Write a single audit_log entry per action
          # Write a single audit_log entry per action
            try:
                client.table("audit_logs").insert(
                    {
                        "organization_id": org_id,
                        "action": f"response.{outcome}.{action.action_type}",
                        "actor_type": "agent",
                        "actor_id": agent_run_id,
                        "actor_name": f"response_agent (run {agent_run_id[:8]})",
                        "target_type": "incident",
                        "target_id": incident["id"],
                        "target_short_id": incident.get("short_id"),
                        "target_name": incident.get("title"),
                        "severity": incident.get("severity"),
                        "status": "completed" if outcome in ("simulated", "executed") else "pending",
                        "reason": action.rationale[:500],
                        "metadata": {
                            "playbook_id": playbook.get("id"),
                            "playbook_name": action.playbook_name,
                            "action_type": action.action_type,
                            "target": action.target,
                            "priority": action.priority,
                            "outcome": outcome,
                            "dry_run": dry_run,
                        },
                    }
                ).execute()
            except Exception:
                log.exception("audit_log_insert_failed")

        verdict.executed_count = executed
        verdict.simulated_count = simulated
        verdict.recommended_count = recommended
        verdict.skipped_count = skipped

        log.info(
            "response_actions_applied",
            incident_short_id=incident.get("short_id"),
            executed=executed,
            simulated=simulated,
            recommended=recommended,
            skipped=skipped,
        )
        return verdict


__all__ = ["ResponseAgent"]