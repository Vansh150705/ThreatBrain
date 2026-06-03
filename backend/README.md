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

FastAPI backend powering the ThreatBrain Neural SOC platform.

- 7 specialized AI agents (Triage, Threat Intel, Investigation, Response, Forensics, Compliance, Hunt)
- Orchestrator endpoint chains them end-to-end
- Multi-tenant via Supabase RLS
- Append-only audit logs
- Real LLM via Groq (LLaMA 3.3 70B)

**Frontend:** https://threat-brain.vercel.app

**API docs:** `/docs` on this Space's URL