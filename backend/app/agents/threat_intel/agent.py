from __future__ import annotations

import json
from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.threat_intel.schemas import ThreatIntelInput, ThreatIntelOutput
from app.core.logging import get_logger
from app.integrations.abuseipdb import (
    AbuseIPDBError,
    check_ip,
    derive_reputation,
)
from app.services.supabase_client import get_supabase_admin

log = get_logger(__name__)


class ThreatIntelAgent(BaseAgent):
    """Enriches an IP with live threat-feed data + LLM synthesis."""

    agent_key = "threat_intel"
    json_mode = True

    def _fetch_abuseipdb(self, ip: str) -> dict[str, Any] | None:
        """Hit AbuseIPDB live; return raw 'data' or None on failure."""
        try:
            return check_ip(ip, max_age_days=90, verbose=True)
        except AbuseIPDBError as exc:
            log.warning(
                "abuseipdb_enrichment_failed",
                ip=ip,
                error=str(exc),
            )
            return None

    def _cache_ioc(
        self,
        *,
        organization_id: str,
        ip: str,
        abuse_data: dict[str, Any],
    ) -> None:
        """Upsert this IP into public.iocs so future agents can reuse it."""
        client = get_supabase_admin()

        abuse_score = int(abuse_data.get("abuseConfidenceScore") or 0)
        reputation = derive_reputation(abuse_score)
        total_reports = int(abuse_data.get("totalReports") or 0)

        # Normalize an ASN value (AbuseIPDB returns "AS12345 ProviderName")
        asn_raw = abuse_data.get("asn") or ""
        asn_num: int | None = None
        if isinstance(asn_raw, str) and asn_raw.upper().startswith("AS"):
            try:
                asn_num = int(asn_raw[2:].split()[0])
            except (ValueError, IndexError):
                asn_num = None

        try:
            # Use upsert via insert with on_conflict handled by the unique index
            client.table("iocs").upsert(
                {
                    "organization_id": organization_id,
                    "ioc_type": "ipv4",
                    "value": ip,
                    "normalized_value": ip,
                    "reputation": reputation,
                    "confidence": min(100, max(0, abuse_score)),
                    "threat_score": min(100, max(0, abuse_score)),
                    "tags": ["abuseipdb"],
                    "source_feeds": ["abuseipdb"],
                    "enrichment": {"abuseipdb": abuse_data},
                    "times_seen": max(1, total_reports),
                    "geo_country": abuse_data.get("countryCode"),
                    "asn": asn_num,
                },
                on_conflict="organization_id,ioc_type,normalized_value",
            ).execute()
            log.info("ioc_cached", ip=ip, reputation=reputation)
        except Exception:
            # Cache failures shouldn't block the agent — log and continue
            log.exception("ioc_cache_failed", ip=ip)


    def build_user_prompt(self, agent_input: AgentInput) -> str:
        """Build the prompt — including live AbuseIPDB data as context."""
        intel_input = ThreatIntelInput.model_validate(agent_input.payload)
        ip = intel_input.ip_address.strip()

        # Fetch live data BEFORE prompting the LLM
        abuse_data = self._fetch_abuseipdb(ip)

        # Stash the raw data on the instance so we can pull it again in
        # validate_output / outer endpoint without a second API call.
        self._last_abuse_data = abuse_data

        # Cache to iocs if we got data and the agent_input contains org context
        org_id = str(agent_input.organization_id)
        if abuse_data:
            self._cache_ioc(organization_id=org_id, ip=ip, abuse_data=abuse_data)

        # Build prompt
        lines: list[str] = [f"IP ADDRESS TO ANALYZE: {ip}", ""]

        if intel_input.context:
            lines.extend(["CONTEXT:", intel_input.context, ""])

        if abuse_data is None:
            lines.extend(
                [
                    "ABUSEIPDB LOOKUP: FAILED OR UNAVAILABLE",
                    "(API rate-limited, key missing, or transient error.)",
                    "",
                    "Without external feed data, base your verdict on the context only "
                    "and mark confidence low.",
                ]
            )
        else:
            score = abuse_data.get("abuseConfidenceScore", 0)
            reports = abuse_data.get("totalReports", 0)
            country = abuse_data.get("countryCode") or "Unknown"
            isp = abuse_data.get("isp") or "Unknown"
            usage_type = abuse_data.get("usageType") or "Unknown"
            last_reported = abuse_data.get("lastReportedAt") or "Never"
            domain = abuse_data.get("domain") or "Unknown"

            lines.extend(
                [
                    "ABUSEIPDB LOOKUP RESULTS (live):",
                    f"  abuseConfidenceScore: {score}/100",
                    f"  totalReports:         {reports}",
                    f"  countryCode:          {country}",
                    f"  isp:                  {isp}",
                    f"  usageType:            {usage_type}",
                    f"  domain:               {domain}",
                    f"  lastReportedAt:       {last_reported}",
                ]
            )

            # Include the first few recent reports if present
            reports_list = abuse_data.get("reports") or []
            if reports_list:
                lines.append("  recentReports:")
                for entry in reports_list[:5]:
                    cats = entry.get("categories") or []
                    when = entry.get("reportedAt", "?")
                    comment = (entry.get("comment") or "").strip()[:120]
                    lines.append(
                        f"    - {when} | categories={cats} | {comment}"
                    )

        lines.extend(
            [
                "",
                "TASK:",
                "Synthesize this into a single JSON object with exactly these fields:",
                "",
                "{",
                f'  "ip_address":        "{ip}",',
                '  "reputation":        one of "benign","unknown","suspicious","malicious",',
                '  "confidence":        integer 0-100 (how sure you are in the verdict),',
                '  "threat_score":      integer 0-100 (aggregate threat severity),',
                '  "severity":          one of "info","low","medium","high","critical",',
                '  "summary":           1-2 sentence analyst-style summary,',
                '  "reasoning":         why you classified it this way, citing the data,',
                '  "country_code":      ISO-2 country code or null,',
                '  "isp":               ISP name or null,',
                '  "usage_type":        e.g. "Data Center/Web Hosting" or null,',
                '  "abuse_score":       integer 0-100 (echo abuseConfidenceScore),',
                '  "total_reports":     integer (echo totalReports),',
                '  "last_reported_at":  string or null (echo lastReportedAt),',
                '  "tags":              array of short labels (["botnet","scanner",...]),',
                '  "raw_feeds":         {"abuseipdb": ...the full data object...}',
                "}",
                "",
                "GUIDELINES:",
                "- abuseConfidenceScore >= 75 → reputation=malicious, severity>=high",
                "- abuseConfidenceScore 40-74 → reputation=suspicious, severity~medium",
                "- abuseConfidenceScore 1-39  → reputation=unknown, severity~low/info",
                "- abuseConfidenceScore 0     → reputation=benign, severity=info",
                "- Hosting/Datacenter IPs warrant higher suspicion than residential",
                "- Be precise — do not invent fields that the feed didn't return.",
            ]
        )

        return "\n".join(lines)

    def validate_output(self, parsed: dict[str, Any]) -> None:
        """Reject responses that don't conform to ThreatIntelOutput."""
        ThreatIntelOutput.model_validate(parsed)


__all__ = ["ThreatIntelAgent"]