from __future__ import annotations

import ipaddress
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

    def __init__(self) -> None:
        super().__init__()
        self._last_incident: dict[str, Any] | None = None
        self._last_threats: list[dict[str, Any]] = []
        self._last_playbooks: list[dict[str, Any]] = []

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
                '      "action_type":    block_ip|block_range|disable_user|isolate_host|notify|quarantine_email|revoke_token|other,',
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
                "- For a DISTRIBUTED / botnet attack (many different source IPs against one target), prefer action_type='block_range' with target as the shared subnet in CIDR notation (e.g. '203.0.113.0/24'); use 'block_ip' when it's a single attacker IP.",
                "- If a legitimate account was compromised (a successful login after many failures), also add a 'disable_user' action targeting that username.",
                "- Don't repeat the same playbook for the same target.",
                "- Set all counts to 0 — the system fills them in after applying.",
                "- If no playbook fits, return empty `actions` and explain in summary.",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _coerce_priority(value: Any) -> int:
        """Normalize a priority into an int in [1, 10]."""
        if isinstance(value, bool):
            return 3
        if isinstance(value, int):
            return max(1, min(10, value))
        if isinstance(value, str):
            words = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}
            token = value.strip().lower()
            if token in words:
                return words[token]
            try:
                return max(1, min(10, int(float(token))))
            except ValueError:
                return 3
        return 3

    def post_process_output(self, parsed: dict[str, Any]) -> dict[str, Any]:
        """Normalize action field types before validation.

        Smaller models occasionally return a non-string ``target`` (or omit it)
        and a worded ``priority`` like "high" instead of an int. Coerce those so
        a stray type slip doesn't fail the whole stage; drop actions that have no
        usable target rather than fabricate one.
        """
        actions = parsed.get("actions")
        if isinstance(actions, list):
            cleaned: list[dict[str, Any]] = []
            for action in actions:
                if not isinstance(action, dict):
                    continue
                target = action.get("target")
                if target is None or (isinstance(target, str) and not target.strip()):
                    continue
                if not isinstance(target, str):
                    action["target"] = str(target)
                action["priority"] = self._coerce_priority(action.get("priority"))
                cleaned.append(action)
            parsed["actions"] = cleaned
        return parsed

    def validate_output(self, parsed: dict[str, Any]) -> None:
        ResponseOutput.model_validate(parsed)

    # --- safety validation -------------------------------------------------
    ALLOWED_ACTIONS = {
        "block_ip", "block_range", "disable_user", "isolate_host",
        "notify", "quarantine_email", "revoke_token", "other",
    }

    def _evidence(self) -> tuple[set[str], set[str]]:
        """(source IPs, affected users) that the incident's threats actually contain."""
        ips: set[str] = set()
        users: set[str] = set()
        for t in self._last_threats or []:
            ips.update(str(i) for i in (t.get("source_ips") or []))
            users.update(str(u).lower() for u in (t.get("affected_users") or []))
        return ips, users

    def _validate_target(self, action: ActionRecommendation) -> str | None:
        """Return a reason string if the action must not be queued, else None.

        The model proposes the target, but the target of anything that touches a
        firewall or an account must come from the incident's own evidence. This
        blocks a prompt-injected "block 8.8.8.8" or "disable the CEO's account".
        """
        kind, target = action.action_type, (action.target or "").strip()
        if not target or len(target) > 200:
            return "empty or oversized target"
        ips, users = self._evidence()
        if kind == "block_ip":
            try:
                addr = ipaddress.ip_address(target)
            except ValueError:
                return f"target is not a valid IP: {target!r}"
            if str(addr) not in ips:
                return "target IP does not appear in this incident's evidence"
        elif kind == "block_range":
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return f"target is not a valid CIDR: {target!r}"
            min_prefix = 16 if net.version == 4 else 32
            if net.prefixlen < min_prefix:
                return f"range too broad (/{net.prefixlen}); minimum is /{min_prefix}"
            if not any(ipaddress.ip_address(i) in net for i in ips if _is_ip(i)):
                return "range does not contain any source IP from this incident's evidence"
        elif kind == "disable_user":
            if target.lower() not in users:
                return "user is not among this incident's affected users"
        return None

    def _already_queued(self, client: Any, org_id: str, incident_id: str, action: ActionRecommendation) -> bool:
        rows = (
            client.table("playbook_approvals")
            .select("id")
            .eq("organization_id", org_id)
            .eq("incident_id", incident_id)
            .eq("action_type", action.action_type)
            .eq("target", action.target)
            .in_("status", ["pending", "approved"])
            .limit(1)
            .execute()
        ).data or []
        return bool(rows)

    def apply_actions(
        self,
        *,
        organization_id: UUID | str,
        verdict: ResponseOutput,
        agent_run_id: str,
        dry_run: bool,
        execute_auto_playbooks: bool = False,
    ) -> ResponseOutput:
        """Validate and record the model's proposed actions. Never executes anything.

        * ``dry_run=True``  -> status ``simulated``: audited, nothing queued.
        * ``dry_run=False`` -> status ``recommended``: queued in
          ``playbook_approvals`` for a human; tb-executor acts only after approval.
        * Anything failing a safety check is ``skipped`` with a ``skip_reason``.
        """
        if execute_auto_playbooks:
            log.warning("response_execute_auto_playbooks_ignored")
        if self._last_incident is None or not verdict.actions:
            return verdict

        client = get_supabase_admin()
        org_id = str(organization_id)
        incident = self._last_incident
        playbooks_by_name = {p["name"]: p for p in (self._last_playbooks or [])}
        incident_confidence = int(incident.get("confidence") or 0)

        simulated = recommended = skipped = 0

        for action in verdict.actions:
            playbook = playbooks_by_name.get(action.playbook_name)
            reason: str | None = None
            if action.action_type not in self.ALLOWED_ACTIONS:
                reason = f"unsupported action type {action.action_type!r}"
            elif playbook is None:
                reason = "playbook is not configured/enabled for this organization"
            elif incident_confidence < int(playbook.get("min_confidence") or 0):
                reason = (
                    f"incident confidence {incident_confidence} is below the playbook "
                    f"minimum of {playbook.get('min_confidence')}"
                )
            else:
                reason = self._validate_target(action)
            if reason is None and not dry_run:
                try:
                    if self._already_queued(client, org_id, incident["id"], action):
                        reason = "an identical action is already pending or approved"
                except Exception:
                    log.exception("playbook_dedupe_check_failed")

            if reason is not None:
                action.status, action.skip_reason = "skipped", reason
                skipped += 1
                log.warning("response_action_skipped", playbook=action.playbook_name, reason=reason)
                outcome = "skipped"
            elif dry_run:
                action.status = "simulated"
                simulated += 1
                outcome = "simulated"
            else:
                action.status = "recommended"
                recommended += 1
                outcome = "recommended"
                try:
                    client.table("playbook_approvals").insert(
                        {
                            "organization_id": org_id,
                            "incident_id": incident["id"],
                            "incident_short_id": incident.get("short_id"),
                            "incident_title": incident.get("title"),
                            "playbook_name": action.playbook_name,
                            "action_type": action.action_type,
                            "target": action.target.strip(),
                            "priority": action.priority,
                            "rationale": (action.rationale or "")[:500],
                            "requested_by": agent_run_id,
                        }
                    ).execute()
                except Exception:
                    log.exception("playbook_approval_insert_failed")
                    action.status, action.skip_reason = "skipped", "could not queue for approval"
                    recommended -= 1
                    skipped += 1
                    outcome = "skipped"

            try:
                client.table("audit_logs").insert(
                    {
                        "organization_id": org_id,
                        "action": f"response.{outcome}.{action.action_type}",
                        "actor_type": "agent",
                        "actor_id": agent_run_id or None,
                        "actor_name": f"response_agent (run {(agent_run_id or 'n/a')[:8]})",
                        "target_type": "incident",
                        "target_id": incident["id"],
                        "target_short_id": incident.get("short_id"),
                        "target_name": incident.get("title"),
                        "severity": incident.get("severity"),
                        "status": "failure" if outcome == "skipped" else "success",
                        "reason": (action.skip_reason or action.rationale or "")[:500],
                        "metadata": {
                            "playbook_id": (playbook or {}).get("id"),
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

        verdict.executed_count = 0
        verdict.simulated_count = simulated
        verdict.recommended_count = recommended
        verdict.skipped_count = skipped

        log.info(
            "response_actions_applied",
            incident_short_id=incident.get("short_id"),
            simulated=simulated,
            recommended=recommended,
            skipped=skipped,
        )
        return verdict


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


__all__ = ["ResponseAgent"]