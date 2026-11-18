"""Deterministic checks on what an LLM claims, run before its output is trusted.

A language model can state things that are not in the evidence: an IP address that never appeared, a CVE it "remembers", a hash,
a file path, an ATT&CK technique id that does not exist. None of that may reach a case file looking as reliable as an
observation. This module checks every concrete, checkable token in the model's prose against the data the model was given and
against MITRE's list of real technique ids, and records what it found:

* unknown ATT&CK ids are dropped (and listed);
* an evidence item whose concrete tokens are not in the event is marked ``verified=false`` (kept, but visibly unverified);
* ungrounded tokens in the headline text, or unverified evidence, cap the confidence the case is filed with.

It never raises a verdict: the severity floor from detection rules is applied by ``reconcile_verdict`` and is unaffected.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from app.agents.triage.schemas import EvidenceItem, TriageOutput
from app.detection import attack_catalog

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|example|local|internal|corp|dev|co|uk|de|fr|onion|cloud|app|tk|cc|su)\b", re.I)
_WINPATH = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|,;]{2,120}")
_NIXPATH = re.compile(r"(?<![\w/])/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|dev|proc|srv|mnt)/[^\s\"'<>|,;]{1,120}")

CONFIDENCE_CAP = 70

# A model that was talked into echoing its instructions or a credential must not have that text filed in a case record.
_SECRET = re.compile(
    r"(sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?i:api[_ -]?key|secret|password|token)\s*[:=]\s*\S{6,})")
_PROMPT_ECHO = re.compile(r"(?i)(system prompt|my (system )?instructions|you are the (triage|response|investigation|forensics|compliance|hunt) agent)")


def redact_leaks(text: str) -> tuple[str, int]:
    n = 0

    def sub(m: re.Match[str]) -> str:
        nonlocal n
        n += 1
        return "[redacted]"

    return _PROMPT_ECHO.sub(sub, _SECRET.sub(sub, text)), n


def _norm(token: str) -> str:
    return token.strip().strip(".,;:)(]['\"").lower().replace("\\", "/")


def entities(text: str) -> set[str]:
    """Concrete, checkable tokens in ``text`` (IPs, hashes, CVEs, domains, e-mail addresses, file paths)."""
    out: set[str] = set()
    for m in _IPV4.finditer(text):
        try:
            out.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            pass
    for rx in (_HASH, _CVE, _EMAIL, _WINPATH, _NIXPATH):
        out.update(_norm(m.group(0)) for m in rx.finditer(text))
    emails = {e.split("@", 1)[1] for e in out if "@" in e}
    out.update(_norm(m.group(0)) for m in _DOMAIN.finditer(text) if _norm(m.group(0)) not in emails)
    return {e for e in out if e}


def source_blob(*parts: Any) -> str:
    """Everything the model was allowed to know, flattened and normalised for substring tests."""
    chunks = []
    for p in parts:
        chunks.append(p if isinstance(p, str) else json.dumps(p, default=str, ensure_ascii=False))
    return _norm("\n".join(chunks)).replace("\\\\", "/")


def supported(entity: str, blob: str) -> bool:
    if entity in blob:
        return True
    if "." in entity and not entity[0].isdigit():       # a domain: any known host that is that domain or a subdomain of it
        return any(tok.endswith(entity) for tok in re.findall(r"[a-z0-9.-]{4,}", blob))
    return False


def ground_triage(verdict: TriageOutput, event: dict[str, Any], detection: dict[str, Any], *extra_sources: Any) -> tuple[TriageOutput, dict[str, Any]]:
    out = verdict.model_copy(deep=True)
    leaked = 0
    for field in ("title", "description", "reasoning"):
        cleaned, n = redact_leaks(getattr(out, field))
        if n:
            setattr(out, field, cleaned)
            leaked += n
    for ev in out.evidence:
        cleaned, n = redact_leaks(ev.detail)
        if n:
            ev.detail = cleaned
            leaked += n
    blob = source_blob(event, detection.get("rules", []), *extra_sources)
    # --- ATT&CK ids must exist
    dropped = [t for t in out.mitre_techniques if t not in attack_catalog.TECHNIQUES]
    dropped_tac = [t for t in out.mitre_tactics if t not in attack_catalog.TACTICS]
    out.mitre_techniques = [t for t in out.mitre_techniques if t in attack_catalog.TECHNIQUES]
    out.mitre_tactics = [t for t in out.mitre_tactics if t in attack_catalog.TACTICS]
    # --- concrete tokens in prose and evidence
    headline = " ".join([out.title, out.description, out.reasoning])
    unsupported_headline = sorted(e for e in entities(headline) if not supported(e, blob))
    checked = len(entities(headline))
    unverified = 0
    items: list[EvidenceItem] = []
    for ev in out.evidence:
        ents = entities(ev.detail)
        checked += len(ents)
        bad = [e for e in ents if not supported(e, blob)]
        if bad and not ev.source.startswith("rule:"):
            unverified += 1
            items.append(EvidenceItem(source=ev.source, detail=ev.detail, verified=False))
        else:
            items.append(EvidenceItem(source=ev.source, detail=ev.detail, verified=True if ents else None))
    out.evidence = items
    capped = False
    if (unsupported_headline or unverified) and out.confidence > CONFIDENCE_CAP:
        out.confidence = CONFIDENCE_CAP
        capped = True
    record = {
        "entities_checked": checked, "unsupported_in_text": unsupported_headline, "evidence_unverified": unverified,
        "dropped_attack_techniques": dropped, "dropped_attack_tactics": dropped_tac, "confidence_capped": capped,
        "secrets_or_prompt_text_redacted": leaked,
    }
    return out, record
