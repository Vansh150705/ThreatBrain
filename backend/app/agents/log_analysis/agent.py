from __future__ import annotations

from typing import Any

from app.agents.base import AgentInput, BaseAgent
from app.agents.log_analysis.schemas import LogAnalysisInput, LogAnalysisOutput
from app.core.logging import get_logger
from app.detection.engine import get_engine
from app.detection.iocs import extract_iocs

log = get_logger(__name__)


class LogAnalysisAgent(BaseAgent):
    """Reads raw log lines, extracts entities and flags suspicious activity.

    The LLM reasons over numbered lines; everything it claims is then checked
    server-side: cited line numbers must exist, extracted entities must literally
    appear in the log, and the deterministic rule engine is run line by line so
    findings carry rule evidence that does not depend on the model.
    """

    agent_key = "log_analysis"
    json_mode = True

    def __init__(self) -> None:
        super().__init__()
        self._lines: list[str] = []

    def build_user_prompt(self, agent_input: AgentInput) -> str:
        params = LogAnalysisInput.model_validate(agent_input.payload)
        self._lines = params.lines
        numbered = "\n".join(f"{i}: {ln}" for i, ln in enumerate(params.lines, start=1))
        return "\n".join(
            [
                f"LOG SOURCE: {params.source_hint or 'unspecified'}",
                f"LINES: {len(params.lines)} (numbered below)",
                "",
                numbered,
                "",
                "TASK:",
                "Analyse these log lines for suspicious or malicious activity. Respond with a single JSON object:",
                "{",
                '  "summary":     2-3 sentence overview of what the log shows,',
                '  "severity":    overall, one of "info","low","medium","high","critical",',
                '  "confidence":  integer 0-100,',
                '  "entities":    {"ips": [], "users": [], "hosts": [], "domains": [], "hashes": []}  (only values that appear in the lines),',
                '  "findings": [',
                '    {"title": "...", "detail": "...", "severity": "...", "evidence_lines": [line numbers], "mitre_techniques": ["T1110"]}',
                "  ],",
                '  "suggested_detections": short descriptions of rules that would catch this activity,',
                '  "reasoning":   why you reached this assessment',
                "}",
                "",
                "GUIDELINES:",
                "- Cite the line numbers that support every finding; never cite a line that does not exist.",
                "- Report only what the lines show. Do not invent IPs, users or events.",
                "- Routine, benign activity should yield severity 'info' and no findings.",
                "- Counting matters: say how many failed attempts, from how many sources, over what period, if the lines show it.",
            ]
        )

    def validate_output(self, parsed: dict[str, Any]) -> None:
        LogAnalysisOutput.model_validate(parsed)

    def post_process_output(self, parsed: dict[str, Any]) -> dict[str, Any]:
        lines = self._lines
        n = len(lines)
        corpus = "\n".join(lines).lower()

        # Entities: keep only what literally occurs in the submitted log.
        entities = parsed.get("entities") if isinstance(parsed.get("entities"), dict) else {}
        verified: dict[str, list[str]] = {}
        for key in ("ips", "users", "hosts", "domains", "hashes"):
            vals = entities.get(key) if isinstance(entities.get(key), list) else []
            verified[key] = [str(v) for v in vals if str(v).strip() and str(v).lower() in corpus][:50]
        # Add IOCs the model missed, via regex extraction.
        found = extract_iocs("\n".join(lines))
        for key in ("ips", "domains", "hashes"):
            for v in found[key]:
                if v not in verified[key]:
                    verified[key].append(v)
        parsed["entities"] = verified

        # Findings: mark whether every cited line exists.
        findings = parsed.get("findings") if isinstance(parsed.get("findings"), list) else []
        for f in findings:
            if not isinstance(f, dict):
                continue
            cited = []
            for x in f.get("evidence_lines") or []:
                try:
                    cited.append(int(x))
                except (TypeError, ValueError):
                    continue
            f["evidence_lines"] = [c for c in cited if 1 <= c <= n]
            f["verified"] = bool(cited) and len(f["evidence_lines"]) == len(cited)
        parsed["findings"] = [f for f in findings if isinstance(f, dict)]

        # Deterministic rule evidence, per line.
        engine = get_engine()
        hits: list[dict[str, Any]] = []
        for i, line in enumerate(lines, start=1):
            for hit in engine.evaluate(
                {"title": line[:200], "event_type": "log.line", "command_line": line, "raw_data": {"line": line}}
            ):
                d = hit.as_dict()
                d["line"] = i
                hits.append(d)
            if len(hits) >= 100:
                break
        parsed["rule_hits"] = hits
        parsed["lines_analyzed"] = n
        return parsed


__all__ = ["LogAnalysisAgent"]
