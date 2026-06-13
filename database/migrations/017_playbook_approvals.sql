-- 017_playbook_approvals.sql
-- queue where the response agent's recommendations wait for a human to approve or reject

CREATE TABLE IF NOT EXISTS public.playbook_approvals (
  id                 UUID         PRIMARY KEY DEFAULT extensions.uuid_generate_v4(),

  organization_id    UUID         NOT NULL
                                  REFERENCES public.organizations(id)
                                  ON DELETE CASCADE,

  incident_id        UUID         REFERENCES public.incidents(id) ON DELETE CASCADE,
  incident_short_id  TEXT,
  incident_title     TEXT,

  -- What the Response Agent recommended
  playbook_name      TEXT         NOT NULL,
  action_type        TEXT         NOT NULL,   -- block_ip | disable_user | isolate_host | ...
  target             TEXT         NOT NULL,   -- IP, user, host, token, ...
  priority           SMALLINT     NOT NULL DEFAULT 5,
  rationale          TEXT,

  -- Decision state
  status             TEXT         NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'approved', 'rejected')),
  requested_by       TEXT,                    -- agent run id that produced the recommendation
  decided_by         UUID         REFERENCES public.users(id) ON DELETE SET NULL,
  decided_by_name    TEXT,
  decision_note      TEXT,
  decided_at         TIMESTAMPTZ,

  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.playbook_approvals IS
  'Response Agent recommendations awaiting human authorization. The agent never executes on its own.';

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_org_status
  ON public.playbook_approvals(organization_id, status, created_at DESC);

-- rls on with no policies, so only the backend service role can touch this table
ALTER TABLE public.playbook_approvals ENABLE ROW LEVEL SECURITY;

-- seed a couple of pending approvals for the demo org
INSERT INTO public.playbook_approvals (
  organization_id, incident_id, incident_short_id, incident_title,
  playbook_name, action_type, target, priority, rationale
) VALUES
  ('00000000-0000-0000-0000-00000000ac01'::uuid,
   '00000000-0000-0000-0000-00000000c001'::uuid,
   'INC-ACT001', 'Suspected APT29 intrusion via SSH brute-force chain',
   'Block Malicious IP', 'block_ip', '203.0.113.42', 9,
   'Primary brute-force source with AbuseIPDB confidence 95. Blocking at the edge firewall cuts the active C2 channel.'),

  ('00000000-0000-0000-0000-00000000ac01'::uuid,
   '00000000-0000-0000-0000-00000000c001'::uuid,
   'INC-ACT001', 'Suspected APT29 intrusion via SSH brute-force chain',
   'Isolate Compromised Host', 'isolate_host', 'prod-web-01 (10.0.1.10)', 8,
   'Reverse shell to 198.51.100.7:4444 is active on this host. Isolation stops lateral movement toward db-prod-master.');
