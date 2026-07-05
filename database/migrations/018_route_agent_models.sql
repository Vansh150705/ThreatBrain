-- 018_route_agent_models.sql
--
-- Route the deterministic / low-stakes agents to the faster, cheaper
-- llama-3.1-8b-instant model, and keep the reasoning-heavy agents on
-- llama-3.3-70b-versatile.
--
-- Why: Groq's daily token limit (TPD) is enforced PER MODEL. Splitting the
-- pipeline across two models means the reactive stages no longer all draw
-- from a single 70b bucket, which is what caused the pipeline to stall once
-- the daily cap was hit.
--
-- Accuracy note: only agents that were verified to produce equivalent output
-- on 8b are moved. Threat Intel is deterministic threshold interpretation
-- (abuse score -> reputation) and produced an identical verdict on 8b. Hunt
-- is proactive/advisory and off the reactive path. Triage, Investigation,
-- Response, Forensics and Compliance stay on 70b because 8b measurably
-- degraded their severity/MITRE/reasoning quality.

update public.agents
set model = 'llama-3.1-8b-instant'
where agent_key in ('threat_intel', 'hunt');

update public.agents
set model = 'llama-3.3-70b-versatile'
where agent_key in ('triage', 'investigation', 'response', 'forensics', 'compliance');
