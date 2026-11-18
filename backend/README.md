---
title: ThreatBrain Backend
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# ThreatBrain Backend

FastAPI backend for the ThreatBrain agentic SOC. See the repository README for the full
architecture, setup and API overview.

- Deterministic detection engine (37 MITRE ATT&CK-mapped rules) + 8 LLM agents
  (Triage, Threat Intel, Investigation, Response, Forensics, Compliance, Hunt, Log Analysis)
- Traced orchestrator: de-duplication, correlation, degraded mode, human-approved response
- Multi-tenant via Supabase (service-role access with explicit org scoping on every query)
- Append-only audit logs, scoped API keys, rate limiting, security headers

```bash
python -m venv venv && ./venv/bin/pip install -r requirements-dev.txt
cp ../.env.example .env        # fill in Supabase + Groq values
./venv/bin/uvicorn app.main:app --reload --port 8000     # docs at /docs
./venv/bin/pytest -q && ./venv/bin/ruff check app tests  # 157 offline tests, no credentials needed
```

**Frontend:** https://threat-brain.vercel.app
