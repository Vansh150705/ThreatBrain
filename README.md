# 🧠 ThreatBrain

**The Neural SOC — Where AI Agents Converge to Defend**

An advanced agentic AI cybersecurity platform where 7 specialized AI agents autonomously detect, investigate, and respond to cyber threats in real-time.

---

## ✨ Features

- 🤖 **7 Specialized AI Agents** working together as a virtual SOC team
- ⚡ **Real-Time Threat Detection** with sub-second event processing
- 🧬 **MITRE ATT&CK Mapping** on every alert
- 🔍 **Auto-Enrichment** via AbuseIPDB, VirusTotal, Shodan, and AlienVault OTX
- 📜 **Compliance Reports** for GDPR, HIPAA, and PCI-DSS
- 🗺️ **Live Attack Map** with geo-visualized threat origins
- 🔗 **N8N Automation** for Slack, Discord, PagerDuty, and 400+ tools

---

## 🤖 The Agents

| Agent | Role |
|-------|------|
| 🚨 Triage | Classifies severity and maps events to MITRE ATT&CK |
| 🔬 Investigation | Correlates events to reconstruct attack chains |
| ⚡ Response | Executes auto-remediation playbooks |
| 🌐 Threat Intel | Enriches IOCs from external intelligence feeds |
| 🕵️ Forensics | Builds incident timelines and root-cause analysis |
| 📋 Compliance | Generates audit-ready compliance reports |
| 🎯 Hunt | Proactively hunts for threats using AI hypotheses |

---

## 🛠️ Tech Stack

**Frontend:** React 18, Vite, TypeScript, Tailwind CSS, Framer Motion, shadcn/ui

**Backend:** FastAPI (Python 3.11), Pydantic v2, LangChain, Groq API (LLaMA 3.3 70B)

**Database:** Supabase (PostgreSQL + pgvector + Realtime + Auth)

**Automation:** N8N

**Deployment:** Vercel + Railway + Supabase

---

## 🚀 Getting Started

### Prerequisites

- Node.js 20+
- Python 3.11+
- Supabase account
- Groq API key

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/ThreatBrain.git
cd ThreatBrain

# Frontend
cd frontend
npm install
npm run dev

# Backend (new terminal)
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Copy `.env.example` to `.env` and add your API keys before running.

---

## 📁 Project Structure

```
ThreatBrain/
├── frontend/     # React + Vite SPA
├── backend/      # FastAPI service with 7 AI agents
├── database/     # Supabase migrations and RLS policies
├── n8n/          # Automation workflows
├── simulator/    # Synthetic log generator
└── docs/         # Documentation
```

---

## 📊 Roadmap

- [x] Project scaffolding
- [ ] Database schema and RLS policies
- [ ] Backend foundation with authentication
- [ ] 7 AI agents
- [ ] Landing page
- [ ] SOC dashboard
- [ ] Real-time event pipeline
- [ ] Log simulator
- [ ] N8N automation workflows
- [ ] Production deployment

---

## 📄 License

MIT License — see [`LICENSE`](./LICENSE) for details.

---

**Built to make defense as autonomous as attack.**

⭐ Star this repo if ThreatBrain inspired you.