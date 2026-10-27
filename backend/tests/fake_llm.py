"""Scriptable stand-in for the Groq SDK client (offline, deterministic)."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any, Callable

Handler = Callable[[str, str], "dict[str, Any] | str"]


def _usage() -> SimpleNamespace:
    return SimpleNamespace(prompt_tokens=100, completion_tokens=50, total_tokens=150)


def default_handler(system: str, user: str) -> dict[str, Any] | str:
    """Plausible, schema-valid output for each agent, driven by the prompt."""
    s = system.lower()
    if "triage agent" in s:
        # judge only the event itself, not the (long) instruction block
        event_part = user.split("TASK:")[0].lower()
        attack = any(
            k in event_part
            for k in ("brute_force", "brute-force", "sql injection", "mimikatz", "ransom", "log4shell", "recon.",
                      "shadow", "vssadmin")
        )
        return {
            "severity": "high" if attack else "info",
            "confidence": 90 if attack else 40,
            "title": "Brute-force attack against SSH" if attack else "Routine event",
            "description": "Repeated failed logins from one source." if attack else "Nothing notable.",
            "reasoning": "Many failed authentications within a short window." if attack else "Benign.",
            "evidence": [{"source": "event", "detail": "event_type indicates an attack"}] if attack else [],
            "mitre_tactics": ["TA0006"] if attack else [],
            "mitre_techniques": ["T1110"] if attack else [],
            "tags": ["brute-force"] if attack else [],
            "promote_to_threat": attack,
        }
    if "threat intel agent" in s:
        return {
            "reputation": "malicious", "confidence": 85, "threat_score": 90, "severity": "high",
            "summary": "Known abusive host.", "reasoning": "High abuse score.", "tags": ["scanner"],
        }
    if "investigation agent" in s:
        ids = re.findall(r"\[(THR-[A-Z0-9]+)\]", user)
        if len(ids) >= 2:
            return {
                "groups": [{
                    "title": "Correlated attack", "summary": "Same source.", "severity": "high",
                    "confidence": 80, "threat_short_ids": ids[:2], "kill_chain_phase": "exploitation",
                    "attribution_hint": None, "reasoning": "Shared IP.",
                }],
                "unrelated_threat_short_ids": ids[2:], "summary": "One cluster.",
            }
        return {"groups": [], "unrelated_threat_short_ids": ids, "summary": "Nothing to correlate."}
    if "response agent" in s:
        ips = re.findall(r"source_ips: \['([0-9a-f.:]+)'", user)
        inc = re.search(r"short_id:\s+(INC-[A-Z0-9]+)", user)
        actions = []
        if ips:
            actions.append({
                "playbook_name": "Block Malicious IP", "action_type": "block_ip",
                "target": ips[0], "priority": 2, "rationale": "Active brute-force source.",
            })
        return {
            "incident_short_id": inc.group(1) if inc else "INC-NONE",
            "overall_severity": "high", "summary": "Block the source.", "actions": actions,
        }
    if "forensics agent" in s:
        inc = re.search(r"short_id:\s+(INC-[A-Z0-9]+)", user)
        threats = re.findall(r"\[(THR-[A-Z0-9]+)\]\s+(\S+)", user)
        return {
            "incident_short_id": inc.group(1) if inc else "INC-NONE", "overall_severity": "high",
            "executive_summary": "Summary.", "attack_narrative": "The attacker guessed passwords.",
            "timeline": [
                {"timestamp": ts, "threat_short_id": tid, "phase": "credential_access",
                 "actor": "203.0.113.42", "target": "web-01", "description": "Brute force observed",
                 "artifacts": []}
                for tid, ts in threats
            ],
            "key_artifacts": ["203.0.113.42"], "evidence_recommendations": ["Preserve auth.log"],
            "affected_assets": ["web-01"], "affected_users": ["root"],
        }
    if "compliance agent" in s:
        inc = re.search(r"short_id:\s+(INC-[A-Z0-9]+)", user)
        return {
            "incident_short_id": inc.group(1) if inc else "INC-NONE",
            "overall_compliance_risk": "medium", "executive_summary": "Summary.",
            "applicable_regulations": ["SOC2"], "mandatory_deadlines": [], "reports": [],
            "recommended_next_steps": ["Review access controls"],
        }
    if "log analysis agent" in s:
        return {
            "summary": "Failed logins from one IP.", "severity": "high", "confidence": 80,
            "entities": {"ips": ["203.0.113.9"], "users": ["root"], "hosts": [], "domains": [], "hashes": []},
            "findings": [{"title": "SSH brute force", "detail": "20 failures", "severity": "high",
                          "evidence_lines": [1], "mitre_techniques": ["T1110"]}],
            "suggested_detections": [], "reasoning": "Repeated failures.",
        }
    if "hunt agent" in s:
        return {"summary": "x", "hypotheses": []}
    return {"answer": "ok"}


class FakeGroq:
    """Records calls; ``handler`` may return a dict (JSON) or a raw string."""

    def __init__(self, handler: Handler | None = None) -> None:
        self.handler = handler or default_handler
        self.calls: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.fail_with is not None:
            raise self.fail_with
        msgs = kwargs["messages"]
        system, user = msgs[0]["content"], msgs[1]["content"]
        out = self.handler(system, user)
        content = out if isinstance(out, str) else json.dumps(out)
        message = SimpleNamespace(content=content)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)], model=kwargs.get("model", "fake-model"),
            usage=_usage(),
        )
