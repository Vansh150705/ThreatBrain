-- 024_agent_key_enterprise.sql
-- Adds the Detection Engineering agent to the agent_key enum.
--
-- IMPORTANT: run this file ON ITS OWN, before 025 (same reason as 022: a new
-- enum value cannot be used in the transaction that adds it).

ALTER TYPE public.agent_key ADD VALUE IF NOT EXISTS 'detection_engineering';
