from __future__ import annotations

from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.threat_intel.schemas import ThreatIntelInput, ThreatIntelOutput
from app.core.logging import get_logger
from app.integrations.abuseipdb import derive_reputation
from app.integrations.intel import enrich_ip
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class ThreatIntelAgent(BaseAgent):
    """Enriches an IP with live multi-feed threat intel + LLM synthesis."""

    agent_key = "threat_intel"
    json_mode = True

    def _cache_ioc(
        self,
        *,
        organization_id: str,
        ip: str,
        intel: dict[str, Any],
    ) -> None:
        """Upsert this IP into public.iocs so future agents can reuse it."""
        feeds = intel.get("feeds") or {}
        if not feeds:
            return
        composite = int(intel.get("composite_score") or 0)
        abuse = feeds.get("abuseipdb") or {}
        vt = feeds.get("virustotal") or {}
        otx_data = feeds.get("otx") or {}

        country = abuse.get("countryCode") or vt.get("country_code") or otx_data.get("country_code")
        asn_num: int | None = None
        asn_raw = abuse.get("asn") or otx_data.get("asn") or ""
        if isinstance(asn_raw, str) and asn_raw.upper().startswith("AS"):
            try:
                asn_num = int(asn_raw[2:].split()[0])
            except (ValueError, IndexError):
                asn_num = None

        try:
            get_supabase_admin().table("iocs").upsert(
                {
                    "organization_id": organization_id,
                    "ioc_type": "ipv4",
                    "value": ip,
                    "normalized_value": ip,
                    "reputation": derive_reputation(composite),
                    "confidence": min(100, max(0, composite)),
                    "threat_score": min(100, max(0, composite)),
                    "tags": sorted(feeds),
                    "source_feeds": sorted(feeds),
                    "enrichment": feeds,
                    "times_seen": max(1, int(abuse.get("totalReports") or 0)),
                    "geo_country": country,
                    "asn": asn_num,
                },
                on_conflict="organization_id,ioc_type,normalized_value",
            ).execute()
            log.info("ioc_cached", ip=ip, feeds=sorted(feeds))
        except Exception:
            # a cache miss shouldn't stop the agent, just log and keep going
            log.exception("ioc_cache_failed", ip=ip)

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        """Build the prompt with live feed data as context."""
        intel_input = ThreatIntelInput.model_validate(agent_input.payload)
        ip = intel_input.ip_address.strip()

        # Fetch live data BEFORE prompting the LLM
        intel = enrich_ip(ip)
        self._intel = intel
        self._ip = ip
        self._last_abuse_data = (intel.get("feeds") or {}).get("abuseipdb")

        if not intel["internal"]:
            self._cache_ioc(
                organization_id=str(agent_input.organization_id), ip=ip, intel=intel
            )

        lines: list[str] = [f"IP ADDRESS TO ANALYZE: {ip}", ""]
        if intel_input.context:
            lines.extend(["CONTEXT:", intel_input.context, ""])

        if intel["internal"]:
            lines.extend(
                [
                    "ADDRESS CLASS: private / loopback / reserved (internal).",
                    "No external feed was queried (internal addresses are never sent to third parties).",
                    "Base the verdict on the context only; external reputation does not apply.",
                ]
            )
        elif not intel["feeds"]:
            lines.extend(
                [
                    "THREAT FEEDS: NONE AVAILABLE",
                    f"(errors: {intel['errors'] or 'no feed configured'})",
                    "",
                    "Without external feed data, base your verdict on the context only "
                    "and mark confidence low.",
                ]
            )
        else:
            abuse = intel["feeds"].get("abuseipdb")
            if abuse:
                lines.extend(
                    [
                        "ABUSEIPDB (live):",
                        f"  abuseConfidenceScore: {abuse.get('abuseConfidenceScore', 0)}/100",
                        f"  totalReports:         {abuse.get('totalReports', 0)}",
                        f"  countryCode:          {abuse.get('countryCode') or 'Unknown'}",
                        f"  isp:                  {abuse.get('isp') or 'Unknown'}",
                        f"  usageType:            {abuse.get('usageType') or 'Unknown'}",
                        f"  domain:               {abuse.get('domain') or 'Unknown'}",
                        f"  lastReportedAt:       {abuse.get('lastReportedAt') or 'Never'}",
                    ]
                )
                for entry in (abuse.get("reports") or [])[:5]:
                    comment = (entry.get("comment") or "").strip()[:120]
                    lines.append(
                        f"    - {entry.get('reportedAt', '?')} | categories={entry.get('categories') or []} | {comment}"
                    )
            vt = intel["feeds"].get("virustotal")
            if vt:
                lines.extend(
                    [
                        "VIRUSTOTAL (live):",
                        f"  malicious engines: {vt['malicious']}, suspicious: {vt['suspicious']}, "
                        f"harmless: {vt['harmless']}, undetected: {vt['undetected']}",
                        f"  as_owner: {vt.get('as_owner') or 'Unknown'}, country: {vt.get('country_code') or 'Unknown'}",
                    ]
                )
            otx_data = intel["feeds"].get("otx")
            if otx_data:
                lines.extend(
                    [
                        "ALIENVAULT OTX (live):",
                        f"  pulses referencing this IP: {otx_data['pulse_count']}",
                        f"  pulse names: {otx_data.get('pulse_names') or []}",
                    ]
                )
            lines.append(f"COMPOSITE THREAT SCORE (server-computed): {intel['composite_score']}/100")
            if intel["errors"]:
                lines.append(f"FEEDS THAT FAILED: {intel['errors']}")

        lines.extend(
            [
                "",
                "TASK:",
                "Analyze the IP and respond with a single JSON object containing ONLY",
                "the analytical fields below. The factual feed fields (country, ISP,",
                "scores, report counts, and the raw feeds) are attached server-side",
                "automatically — do NOT echo them back, it wastes tokens.",
                "",
                "{",
                '  "reputation":    one of "benign","unknown","suspicious","malicious",',
                '  "confidence":    integer 0-100 (how sure you are in the verdict),',
                '  "threat_score":  integer 0-100 (aggregate threat severity),',
                '  "severity":      one of "info","low","medium","high","critical",',
                '  "summary":       1-2 sentence analyst-style summary,',
                '  "reasoning":     why you classified it this way, citing the data,',
                '  "tags":          array of short labels (["botnet","scanner",...])',
                "}",
                "",
                "GUIDELINES:",
                "- composite score >= 75 → reputation=malicious, severity>=high",
                "- composite score 40-74 → reputation=suspicious, severity~medium",
                "- composite score 1-39  → reputation=unknown, severity~low/info",
                "- composite score 0     → reputation=benign, severity=info",
                "- Hosting/Datacenter IPs warrant higher suspicion than residential",
                "- Be precise — do not invent details the feeds didn't return.",
            ]
        )

        return "\n".join(lines)

    def post_process_output(self, parsed: dict[str, Any]) -> dict[str, Any]:
        """Attach the factual feed fields server-side.

        The LLM provides the analytical narrative; scores, counts, the raw feeds
        and (when feed data exists) the reputation bucket come from the feeds
        themselves, so those fields are verbatim-accurate rather than transcribed
        or second-guessed by the model.
        """
        ip = getattr(self, "_ip", None)
        if ip:
            parsed["ip_address"] = ip

        intel = getattr(self, "_intel", None) or {}
        feeds = intel.get("feeds") or {}
        parsed["internal"] = bool(intel.get("internal"))
        parsed["feeds_used"] = sorted(feeds)
        parsed["feed_errors"] = intel.get("errors") or {}
        parsed["feed_scores"] = intel.get("scores") or {}
        parsed["composite_score"] = intel.get("composite_score")
        parsed["raw_feeds"] = feeds

        if feeds:
            def _clean(value: Any) -> Any:
                return value if value not in (None, "", "Unknown") else None

            abuse = feeds.get("abuseipdb") or {}
            vt = feeds.get("virustotal") or {}
            otx_data = feeds.get("otx") or {}
            parsed["country_code"] = _clean(
                abuse.get("countryCode") or vt.get("country_code") or otx_data.get("country_code")
            )
            parsed["isp"] = _clean(abuse.get("isp") or vt.get("as_owner"))
            parsed["usage_type"] = _clean(abuse.get("usageType"))
            parsed["abuse_score"] = int(abuse.get("abuseConfidenceScore") or 0)
            parsed["total_reports"] = int(abuse.get("totalReports") or 0)
            parsed["last_reported_at"] = _clean(abuse.get("lastReportedAt"))
            # Factual bucket comes from the feeds, not from the model.
            parsed["reputation"] = derive_reputation(int(intel.get("composite_score") or 0))
        return parsed

    def validate_output(self, parsed: dict[str, Any]) -> None:
        """Reject responses that don't conform to ThreatIntelOutput."""
        ThreatIntelOutput.model_validate(parsed)


__all__ = ["ThreatIntelAgent"]
