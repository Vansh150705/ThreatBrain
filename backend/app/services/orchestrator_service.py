from __future__ import annotations

from typing import Any
from uuid import UUID

from app.agents.base import AgentInput
from app.agents.compliance import ComplianceAgent, ComplianceInput
from app.agents.forensics import ForensicsAgent, ForensicsInput
from app.agents.investigation import InvestigationAgent, InvestigationInput
from app.agents.response import ResponseAgent, ResponseInput
from app.agents.threat_intel import ThreatIntelAgent, ThreatIntelInput
from app.agents.triage import TriageAgent, TriageInput, TriageOutput
from app.core.logging import get_logger

log = get_logger(__name__)

# Stage result wrapper

def _stage(status: str, **kwargs: Any) -> dict[str, Any]:
    """Build a uniform per-stage result dict."""
    return {"status": status, **kwargs}

# Main pipeline

def run_full_pipeline(
    *,
    organization_id: UUID | str,
    event: TriageInput,
    primary_asset_id: str | None = None,
    promote_threats: bool = True,
    run_threat_intel: bool = True,
    run_investigation: bool = True,
    run_response: bool = True,
    run_forensics: bool = True,
    run_compliance: bool = True,
    investigation_lookback_hours: int = 168,
) -> dict[str, Any]:


    org_id = str(organization_id)
    stages: dict[str, dict[str, Any]] = {}

    # Stage 1: Triage
    triage_run_id: str | None = None
    promoted_threat_id: str | None = None
    triage_verdict: TriageOutput | None = None
    try:
        agent = TriageAgent()
        run_result = agent.run(
            AgentInput(
                organization_id=organization_id,
                trigger_type="chained",
                payload=event.model_dump(),
            )
        )
        triage_run_id = run_result.run_id
        triage_verdict = TriageOutput.model_validate(run_result.output)

        if promote_threats and triage_verdict.promote_to_threat:
            promoted_threat_id = agent.promote_to_threat(
                organization_id=organization_id,
                triage_input=event,
                triage_output=triage_verdict,
                agent_run_id=triage_run_id,
                primary_asset_id=primary_asset_id,
            )

        stages["triage"] = _stage(
            "ok",
            run_id=triage_run_id,
            verdict=triage_verdict.model_dump(),
            promoted_threat_id=promoted_threat_id,
            latency_ms=run_result.latency_ms,
            tokens=run_result.total_tokens,
        )
    except Exception as exc:
        log.exception("orchestrator_triage_failed")
        stages["triage"] = _stage("failed", error=str(exc))

    # Stage 2: Threat Intel (if IP present)
    if not run_threat_intel:
        stages["threat_intel"] = _stage("skipped", reason="disabled by flag")
    elif not event.source_ip:
        stages["threat_intel"] = _stage("skipped", reason="no source_ip in event")
    else:
        try:
            agent = ThreatIntelAgent()
            run_result = agent.run(
                AgentInput(
                    organization_id=organization_id,
                    trigger_type="chained",
                    payload=ThreatIntelInput(
                        ip_address=event.source_ip,
                        context=event.description or event.title,
                    ).model_dump(),
                )
            )
            stages["threat_intel"] = _stage(
                "ok",
                run_id=run_result.run_id,
                verdict=run_result.output,
                latency_ms=run_result.latency_ms,
                tokens=run_result.total_tokens,
            )
        except Exception as exc:
            log.exception("orchestrator_threat_intel_failed")
            stages["threat_intel"] = _stage("failed", error=str(exc))

    # Stage 3: Investigation
    incident_short_id: str | None = None
    incident_id: str | None = None
    if not run_investigation:
        stages["investigation"] = _stage("skipped", reason="disabled by flag")
    else:
        try:
            agent = InvestigationAgent()
            run_result = agent.run(
                AgentInput(
                    organization_id=organization_id,
                    trigger_type="chained",
                    payload=InvestigationInput(
                        lookback_hours=investigation_lookback_hours,
                        max_threats=30,
                        min_severity="low",
                    ).model_dump(),
                )
            )

            from app.agents.investigation import InvestigationOutput

            verdict = InvestigationOutput.model_validate(run_result.output)
            incidents_created = agent.create_incidents_from_output(
                organization_id=organization_id,
                verdict=verdict,
                agent_run_id=run_result.run_id,
            )

            if incidents_created:
                incident_short_id = incidents_created[0].get("short_id")
                incident_id = incidents_created[0].get("incident_id")

            stages["investigation"] = _stage(
                "ok",
                run_id=run_result.run_id,
                verdict=verdict.model_dump(),
                incidents_created=incidents_created,
                latency_ms=run_result.latency_ms,
                tokens=run_result.total_tokens,
            )
        except Exception as exc:
            log.exception("orchestrator_investigation_failed")
            stages["investigation"] = _stage("failed", error=str(exc))

    # Stages 4-6 need an incident to act on
    if incident_short_id is None:
        skip_reason = "no incident produced by Investigation"
        if not run_response:
            stages["response"] = _stage("skipped", reason="disabled by flag")
        else:
            stages["response"] = _stage("skipped", reason=skip_reason)

        if not run_forensics:
            stages["forensics"] = _stage("skipped", reason="disabled by flag")
        else:
            stages["forensics"] = _stage("skipped", reason=skip_reason)

        if not run_compliance:
            stages["compliance"] = _stage("skipped", reason="disabled by flag")
        else:
            stages["compliance"] = _stage("skipped", reason=skip_reason)
    else:
        # Stage 4: Response (dry-run by default)
        if not run_response:
            stages["response"] = _stage("skipped", reason="disabled by flag")
        else:
            try:
                agent = ResponseAgent()
                run_result = agent.run(
                    AgentInput(
                        organization_id=organization_id,
                        trigger_type="chained",
                        payload=ResponseInput(
                            incident_short_id=incident_short_id,
                            dry_run=True,
                            execute_auto_playbooks=False,
                        ).model_dump(),
                    )
                )
                from app.agents.response import ResponseOutput

                verdict = ResponseOutput.model_validate(run_result.output)
                verdict = agent.apply_actions(
                    organization_id=organization_id,
                    verdict=verdict,
                    agent_run_id=run_result.run_id,
                    dry_run=True,
                    execute_auto_playbooks=False,
                )
                stages["response"] = _stage(
                    "ok",
                    run_id=run_result.run_id,
                    verdict=verdict.model_dump(),
                    latency_ms=run_result.latency_ms,
                    tokens=run_result.total_tokens,
                )
            except Exception as exc:
                log.exception("orchestrator_response_failed")
                stages["response"] = _stage("failed", error=str(exc))

        # Stage 5: Forensics
        if not run_forensics:
            stages["forensics"] = _stage("skipped", reason="disabled by flag")
        else:
            try:
                agent = ForensicsAgent()
                run_result = agent.run(
                    AgentInput(
                        organization_id=organization_id,
                        trigger_type="chained",
                        payload=ForensicsInput(
                            incident_short_id=incident_short_id,
                        ).model_dump(),
                    )
                )
                stages["forensics"] = _stage(
                    "ok",
                    run_id=run_result.run_id,
                    verdict=run_result.output,
                    latency_ms=run_result.latency_ms,
                    tokens=run_result.total_tokens,
                )
            except Exception as exc:
                log.exception("orchestrator_forensics_failed")
                stages["forensics"] = _stage("failed", error=str(exc))

        # Stage 6: Compliance 
        if not run_compliance:
            stages["compliance"] = _stage("skipped", reason="disabled by flag")
        else:
            try:
                agent = ComplianceAgent()
                run_result = agent.run(
                    AgentInput(
                        organization_id=organization_id,
                        trigger_type="chained",
                        payload=ComplianceInput(
                            incident_short_id=incident_short_id,
                        ).model_dump(),
                    )
                )
                stages["compliance"] = _stage(
                    "ok",
                    run_id=run_result.run_id,
                    verdict=run_result.output,
                    latency_ms=run_result.latency_ms,
                    tokens=run_result.total_tokens,
                )
            except Exception as exc:
                log.exception("orchestrator_compliance_failed")
                stages["compliance"] = _stage("failed", error=str(exc))

    # Summary
    summary = {
        "stages_run": sum(1 for s in stages.values() if s["status"] != "skipped"),
        "stages_succeeded": sum(1 for s in stages.values() if s["status"] == "ok"),
        "stages_failed": sum(1 for s in stages.values() if s["status"] == "failed"),
        "stages_skipped": sum(1 for s in stages.values() if s["status"] == "skipped"),
        "incident_short_id": incident_short_id,
        "promoted_threat_id": promoted_threat_id,
    }

    log.info("orchestrator_pipeline_completed", **summary)

    return {"stages": stages, "summary": summary}


__all__ = ["run_full_pipeline"]