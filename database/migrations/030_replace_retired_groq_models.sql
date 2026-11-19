-- 030_replace_retired_groq_models.sql
-- Groq retired llama-3.1-8b-instant and llama-3.3-70b-versatile: the API now answers 404 "model does not exist", so every LLM
-- agent failed (the pipeline ran detection rules and then stopped at Triage). Move the existing agent rows to the current
-- equivalents. The backend also maps the retired names at call time (RETIRED_GROQ_MODELS in llm_service.py), which covers rows
-- created later by the older seed functions, so this migration only keeps the stored data honest.
--   llama-3.1-8b-instant    -> openai/gpt-oss-20b   (fast tier)
--   llama-3.3-70b-versatile -> openai/gpt-oss-120b  (reasoning tier)
-- Idempotent: rows already on a current model are untouched.
UPDATE public.agents SET model = 'openai/gpt-oss-20b'  WHERE model = 'llama-3.1-8b-instant';
UPDATE public.agents SET model = 'openai/gpt-oss-120b' WHERE model = 'llama-3.3-70b-versatile';
ALTER TABLE public.agents ALTER COLUMN model SET DEFAULT 'openai/gpt-oss-120b';
