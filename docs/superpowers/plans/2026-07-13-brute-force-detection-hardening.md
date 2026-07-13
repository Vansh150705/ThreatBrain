# Brute-Force Detection Hardening — Design & Plan (Phase 5)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]`.

**Goal:** Make `tb-collector` detect the full spectrum of brute-force tradecraft (MITRE T1110.*) across services, not just single-IP SSH guessing — and emit events that carry the right severity so ThreatBrain escalates and (on approval) blocks.

**Architecture:** Two layers. **Parsers** turn a raw log line from any source into a common `AuthEvent(service, source_ip, username, outcome, timestamp, count, raw)`. **Detectors** consume the `AuthEvent` stream and each catch one attack *technique* (service-agnostic). A `DetectionEngine` wires parsers → detectors and returns zero-or-more `Detection`s per line. Adding a protocol = adding one parser; the detectors are reused for all.

**Tech Stack:** Python 3.11, pytest (pure-logic TDD). Extends the existing `collector/tb_collector` package.

## Global Constraints

- Pure detection/defence. Parsers accept real log formats; no attack tooling.
- Commit style: Conventional Commits; author = repo owner only (no Claude co-author).
- All detectors map to a MITRE technique and carry a severity hint; false-positive control via thresholds + cooldowns.
- rsyslog compresses floods into `message repeated N times: [ <line> ]` — the engine MUST expand these (count = N) or floods are undercounted.

## The common event

```python
@dataclass
class AuthEvent:
    service: str            # "ssh" | "sudo" | "ftp" | "smtp" | "imap" | "web" | "winrdp" | ...
    source_ip: str | None
    username: str | None
    outcome: str           # "fail" | "invalid" | "success"
    timestamp: float       # epoch seconds
    raw: str
    count: int = 1         # >1 when rsyslog-compressed
```
`invalid` = auth failure for a non-existent account (drives username-enumeration detection).

## The six detectors (service-agnostic, MITRE-mapped)

| Detector | Fires when | MITRE | Severity |
|---|---|---|---|
| `PerSourceGuessing` | one source_ip reaches N fails within a short window | T1110.001 | high |
| `SuccessAfterFailure` | a `success` from an ip/user that had >=K recent fails | T1110 → T1078 | **critical** (breach) |
| `PasswordSpraying` | one source_ip fails against >=U distinct usernames in a window | T1110.003 | high |
| `UsernameEnumeration` | one source_ip produces >=V distinct `invalid` users in a window | T1087 | medium→high |
| `DistributedBruteForce` | one target username is failed by >=W distinct source_ips in a window | T1110.001 | high |
| `LowAndSlow` | one source_ip reaches a low count over a long (hours) window | T1110.001 | high |

Each detector keeps its own state + cooldown so one attack is one event. `SuccessAfterFailure` ignores cooldown (a live compromise must always surface). `Detection` gains `severity: str`, `mitre: list[str]`, and `extra: dict` (e.g. distinct users/ips, target user, all offending ips).

## Parsers (this phase: SSH/auth; next phase: the rest)

Phase 5a (now, testable on Kali via `/var/log/auth.log`):
- **sshd**: `Failed password for [invalid user] <u> from <ip>`, `Accepted password|publickey for <u> from <ip>` (success), `Invalid user <u> from <ip>`, `Connection closed by authenticating user <u> <ip> ... [preauth]`, `Disconnected from authenticating user`.
- **pam_unix**: `authentication failure; ... rhost=<ip> user=<u>` (sshd/login).
- **sudo/su**: `authentication failure` / `FAILED su` → local privilege brute.
- rsyslog `message repeated N times: [ <inner> ]` expansion in the engine.

Phase 5b (next):
- **web** (nginx/apache access log): repeated `POST /login|/wp-login|/api/*token*` with 401/403 (and 200 after failures = stuffing success). Handles `X-Forwarded-For` when present.
- **ftp** (vsftpd/proftpd), **mail** (postfix/dovecot SASL `LOGIN authentication failed`), **Windows RDP** (Event ID 4625 / 4624) from exported/forwarded event text.

## Backend escalation (next phase)

Extend the Triage prompt so the new event phrasings map cleanly: a successful login after repeated failures = **critical** confirmed compromise (promote); password spraying / credential stuffing / distributed = **high** (promote). The single-threat-incident fallback then drives the block recommendation as today.

## Tasks (Phase 5a — this build)

1. `AuthEvent` model + `Detection` fields (`severity`, `mitre`, `extra`) — TDD.
2. Parser layer: `parse_auth_line(line) -> AuthEvent | None` (sshd + pam + sudo) with rsyslog expansion — TDD with real sample lines.
3. The six detectors — TDD each with crafted event sequences.
4. `DetectionEngine(parsers, detectors).process_line(line, now) -> list[Detection]` — TDD.
5. Normalizer: `detection_to_ingest_payload` carries `event_type`, severity-laden `title/description`, and `extra` in `raw_data`.
6. Rewire `runner.py` to use the engine (post each detection). Update/replace the old `AuthLogSSHBruteForce` tests.
7. Full `pytest` green; commit per task.

## Definition of Done (5a)

- Engine detects all six techniques from `auth.log` sample lines, with rsyslog expansion and success/compromise detection, in unit tests.
- `python -m tb_collector` tails auth.log and posts richer, correctly-typed events.
- Old single-IP behaviour preserved (now one of six detectors).
