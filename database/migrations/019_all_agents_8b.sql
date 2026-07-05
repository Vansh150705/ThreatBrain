-- 019_all_agents_8b.sql
--
-- Supersedes 018. Move ALL agents to llama-3.1-8b-instant.
--
-- Why: maximize free-tier throughput so demo visitors can run many more
-- pipelines. Groq's daily token limit is enforced per model, and 8b-instant
-- has a much larger daily allowance than the 70b model that was capping out.
--
-- Accuracy note: every agent was verified to produce schema-valid output on 8b
-- with its real prompt (no failed stages). The remaining quality gap vs 70b is
-- subtle — severity nuance and MITRE-technique precision — and not material for
-- the demo audience, who cannot tell the two models apart from the pipeline run.

update public.agents
set model = 'llama-3.1-8b-instant';
