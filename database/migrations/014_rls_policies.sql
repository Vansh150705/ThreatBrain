CREATE OR REPLACE FUNCTION public.current_user_org_id()
RETURNS UUID
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT organization_id
  FROM public.users
  WHERE id = auth.uid()
    AND deleted_at IS NULL
  LIMIT 1;
$$;

COMMENT ON FUNCTION public.current_user_org_id() IS
  'Returns the organization_id of the currently authenticated user. NULL if not authenticated.';


CREATE OR REPLACE FUNCTION public.current_user_role()
RETURNS public.user_role
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role
  FROM public.users
  WHERE id = auth.uid()
    AND deleted_at IS NULL
  LIMIT 1;
$$;

COMMENT ON FUNCTION public.current_user_role() IS
  'Returns the role of the currently authenticated user.';


CREATE OR REPLACE FUNCTION public.is_org_member(p_org_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.users
    WHERE id = auth.uid()
      AND organization_id = p_org_id
      AND deleted_at IS NULL
  );
$$;

CREATE OR REPLACE FUNCTION public.is_at_least_analyst()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.current_user_role() IN ('owner', 'admin', 'analyst');
$$;

CREATE OR REPLACE FUNCTION public.is_at_least_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.current_user_role() IN ('owner', 'admin');
$$;

CREATE OR REPLACE FUNCTION public.is_owner()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.current_user_role() = 'owner';
$$;



DROP POLICY IF EXISTS "organizations_select_members"   ON public.organizations;
DROP POLICY IF EXISTS "organizations_insert_anyone"    ON public.organizations;
DROP POLICY IF EXISTS "organizations_update_admins"    ON public.organizations;
DROP POLICY IF EXISTS "organizations_delete_owners"    ON public.organizations;

CREATE POLICY "organizations_select_members"
  ON public.organizations FOR SELECT
  TO authenticated
  USING (public.is_org_member(id));

-- Anyone authenticated can create an org (they become its owner via app logic)
CREATE POLICY "organizations_insert_anyone"
  ON public.organizations FOR INSERT
  TO authenticated
  WITH CHECK (TRUE);

CREATE POLICY "organizations_update_admins"
  ON public.organizations FOR UPDATE
  TO authenticated
  USING (public.is_org_member(id) AND public.is_at_least_admin())
  WITH CHECK (public.is_org_member(id) AND public.is_at_least_admin());

CREATE POLICY "organizations_delete_owners"
  ON public.organizations FOR DELETE
  TO authenticated
  USING (public.is_org_member(id) AND public.is_owner());


DROP POLICY IF EXISTS "users_select_same_org"     ON public.users;
DROP POLICY IF EXISTS "users_update_self_or_admin" ON public.users;
DROP POLICY IF EXISTS "users_delete_admins"       ON public.users;

CREATE POLICY "users_select_same_org"
  ON public.users FOR SELECT
  TO authenticated
  USING (
    id = auth.uid()
    OR organization_id = public.current_user_org_id()
  );

CREATE POLICY "users_update_self_or_admin"
  ON public.users FOR UPDATE
  TO authenticated
  USING (
    id = auth.uid()
    OR (organization_id = public.current_user_org_id() AND public.is_at_least_admin())
  )
  WITH CHECK (
    id = auth.uid()
    OR (organization_id = public.current_user_org_id() AND public.is_at_least_admin())
  );

CREATE POLICY "users_delete_admins"
  ON public.users FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
    AND id <> auth.uid()                                -- can't delete yourself
  );



DROP POLICY IF EXISTS "assets_select" ON public.assets;
DROP POLICY IF EXISTS "assets_insert" ON public.assets;
DROP POLICY IF EXISTS "assets_update" ON public.assets;
DROP POLICY IF EXISTS "assets_delete" ON public.assets;

CREATE POLICY "assets_select"
  ON public.assets FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "assets_insert"
  ON public.assets FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "assets_update"
  ON public.assets FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "assets_delete"
  ON public.assets FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );


DROP POLICY IF EXISTS "events_select" ON public.events;
DROP POLICY IF EXISTS "events_insert" ON public.events;
DROP POLICY IF EXISTS "events_update" ON public.events;
DROP POLICY IF EXISTS "events_delete" ON public.events;

CREATE POLICY "events_select"
  ON public.events FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "events_insert"
  ON public.events FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "events_update"
  ON public.events FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "events_delete"
  ON public.events FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );

DROP POLICY IF EXISTS "threats_select" ON public.threats;
DROP POLICY IF EXISTS "threats_insert" ON public.threats;
DROP POLICY IF EXISTS "threats_update" ON public.threats;
DROP POLICY IF EXISTS "threats_delete" ON public.threats;

CREATE POLICY "threats_select"
  ON public.threats FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "threats_insert"
  ON public.threats FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "threats_update"
  ON public.threats FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "threats_delete"
  ON public.threats FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );



DROP POLICY IF EXISTS "incidents_select" ON public.incidents;
DROP POLICY IF EXISTS "incidents_insert" ON public.incidents;
DROP POLICY IF EXISTS "incidents_update" ON public.incidents;
DROP POLICY IF EXISTS "incidents_delete" ON public.incidents;

CREATE POLICY "incidents_select"
  ON public.incidents FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "incidents_insert"
  ON public.incidents FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "incidents_update"
  ON public.incidents FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "incidents_delete"
  ON public.incidents FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );



DROP POLICY IF EXISTS "agents_select"        ON public.agents;
DROP POLICY IF EXISTS "agents_update_admins" ON public.agents;

CREATE POLICY "agents_select"
  ON public.agents FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "agents_update_admins"
  ON public.agents FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );


DROP POLICY IF EXISTS "agent_runs_select" ON public.agent_runs;
DROP POLICY IF EXISTS "agent_runs_insert" ON public.agent_runs;
DROP POLICY IF EXISTS "agent_runs_update" ON public.agent_runs;

CREATE POLICY "agent_runs_select"
  ON public.agent_runs FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "agent_runs_insert"
  ON public.agent_runs FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "agent_runs_update"
  ON public.agent_runs FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );


DROP POLICY IF EXISTS "iocs_select" ON public.iocs;
DROP POLICY IF EXISTS "iocs_insert" ON public.iocs;
DROP POLICY IF EXISTS "iocs_update" ON public.iocs;
DROP POLICY IF EXISTS "iocs_delete" ON public.iocs;

CREATE POLICY "iocs_select"
  ON public.iocs FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "iocs_insert"
  ON public.iocs FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "iocs_update"
  ON public.iocs FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "iocs_delete"
  ON public.iocs FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );


DROP POLICY IF EXISTS "playbooks_select" ON public.playbooks;
DROP POLICY IF EXISTS "playbooks_insert" ON public.playbooks;
DROP POLICY IF EXISTS "playbooks_update" ON public.playbooks;
DROP POLICY IF EXISTS "playbooks_delete" ON public.playbooks;

CREATE POLICY "playbooks_select"
  ON public.playbooks FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "playbooks_insert"
  ON public.playbooks FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "playbooks_update"
  ON public.playbooks FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "playbooks_delete"
  ON public.playbooks FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );


DROP POLICY IF EXISTS "audit_logs_select" ON public.audit_logs;

CREATE POLICY "audit_logs_select"
  ON public.audit_logs FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());


DROP POLICY IF EXISTS "agent_memory_select" ON public.agent_memory;
DROP POLICY IF EXISTS "agent_memory_insert" ON public.agent_memory;
DROP POLICY IF EXISTS "agent_memory_update" ON public.agent_memory;
DROP POLICY IF EXISTS "agent_memory_delete" ON public.agent_memory;

CREATE POLICY "agent_memory_select"
  ON public.agent_memory FOR SELECT
  TO authenticated
  USING (organization_id = public.current_user_org_id());

CREATE POLICY "agent_memory_insert"
  ON public.agent_memory FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "agent_memory_update"
  ON public.agent_memory FOR UPDATE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  )
  WITH CHECK (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_analyst()
  );

CREATE POLICY "agent_memory_delete"
  ON public.agent_memory FOR DELETE
  TO authenticated
  USING (
    organization_id = public.current_user_org_id()
    AND public.is_at_least_admin()
  );
