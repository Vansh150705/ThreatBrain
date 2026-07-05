-- 020_cap_agent_max_tokens.sql
--
-- Cap every agent's completion budget at 2048 tokens.
--
-- Why: with all agents on llama-3.1-8b-instant (migration 019), the free tier
-- limits a single request to 6000 tokens/minute (TPM), counting the prompt plus
-- the reserved max_tokens. Forensics and Compliance had max_tokens of 6144 and
-- 8192, so their requests (prompt + reservation) exceeded 6000 and were rejected
-- with a 413 "request too large". 2048 sits comfortably above the largest real
-- completion (~1200 tokens) while leaving ample room for the prompt under the
-- TPM ceiling.

update public.agents
set max_tokens = 2048;
