# Deployment

ThreatBrain ships as **three independently deployed pieces**. The trap to avoid:
the frontend and backend live in the same working tree but deploy from **two
different git repos** to **two different hosts**. A backend change is not live
until it is pushed to *both* remotes.

```
                         ┌─────────────────────────────────────────┐
  threat-brain.vercel.app│  Frontend (React + Vite)                │
        (Vercel)         │  auto-deploys on push to `origin/main`  │
                         └──────────────────┬──────────────────────┘
                                            │  calls VITE_API_BASE_URL
                                            ▼
        vansh150705-threatbrain-backend.hf.space  ┌───────────────────────────┐
              (Hugging Face Spaces, Docker)        │  Backend (FastAPI)        │
              deploys on push to `space` remote    │  from backend/.git        │
                                            │       └────────────┬──────────────┘
                                            │                    │
                                            ▼                    ▼
                                     Supabase Postgres (Auth + RLS + Realtime)
                                     schema changes run manually in SQL editor
```

## The two git repos

| Path | Remote | Pushes to | Hosts |
|------|--------|-----------|-------|
| `./` (repo root) | `origin` | github.com/Vansh150705/ThreatBrain | source of truth; Vercel watches it |
| `./backend` | `space` | huggingface.co/spaces/Vansh150705/threatbrain-backend | the live backend |

The repo root **also tracks** the `backend/` files (for GitHub history), so
backend code exists in both repos. The root repo does **not** deploy the
backend — only the nested `backend/.git` → `space` does.

## What to push, when

### Frontend-only change (pages, components, styles, index.html)
```bash
git add <files> && git commit -m "..."
git push origin main          # Vercel auto-deploys within ~1 min
```

### Backend change (anything under backend/app, requirements, Dockerfile)
Push to **both** remotes — `origin` for history, `space` to actually deploy:
```bash
# 1. main repo (GitHub history)
git add backend/<files> && git commit -m "..."
git push origin main

# 2. backend deploy repo (Hugging Face Spaces)
cd backend
git add <files> && git commit -m "..."
git push space HEAD:main      # triggers Docker rebuild (~2-3 min)
cd ..
```

Verify the rebuild by polling a new route until it stops returning 404
(an auth-protected route returns 401 once it is registered):
```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  https://vansh150705-threatbrain-backend.hf.space/api/v1/health   # 200 = up
```

### Database / schema change
Migrations in `database/migrations/` are **not applied automatically**. Run the
SQL manually in the Supabase SQL editor (Dashboard → SQL Editor), then deploy
any backend code that depends on the new schema. A new table/column without the
backend code that reads it does nothing; backend code without the table 500s.
Run the migration **first**, then push the backend.

## Environment variables

Secrets are configured per host, never committed:

- **Vercel** (frontend): `VITE_API_BASE_URL` (points at the HF Spaces backend),
  `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`. Local dev uses
  `frontend/.env.local` with `VITE_API_BASE_URL=http://localhost:8000/api/v1`.
- **Hugging Face Spaces** (backend): `SUPABASE_URL`, `SUPABASE_ANON_KEY`,
  `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_JWT_SECRET`, `GROQ_API_KEY`. Set under
  the Space's Settings → Variables and secrets.

## Local development

```bash
# backend  (http://localhost:8000)
cd backend && ./venv/Scripts/python.exe -m uvicorn app.main:app --port 8000

# frontend (http://localhost:5173) — reads frontend/.env.local
cd frontend && npm run dev
```

## Common symptom → cause

| Symptom | Cause |
|---------|-------|
| New page shows `404: Not Found` from the API | Backend code pushed to `origin` but not to `space`. Push to `space`. |
| Feature works locally, not in production | Same — the HF Spaces backend is behind. |
| `500` referencing a missing table/column | Migration not run in Supabase yet. |
| Frontend change not live | Check the Vercel deployment finished; it follows `origin/main`. |
