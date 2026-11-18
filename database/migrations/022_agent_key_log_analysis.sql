-- 022_agent_key_log_analysis.sql
-- Adds the Log Analysis agent to the agent_key enum.
--
-- IMPORTANT: run this file ON ITS OWN, before 023. PostgreSQL cannot use a new
-- enum value in the same transaction that adds it, and the Supabase SQL editor
-- runs a pasted script as one transaction.

ALTER TYPE public.agent_key ADD VALUE IF NOT EXISTS 'log_analysis';
