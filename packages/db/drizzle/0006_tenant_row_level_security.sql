-- Tenant isolation, as row-level security.
--
-- The compiler is the first defence: every repository function demands a scope
-- value that cannot be written down by hand, so a query that has not proved its
-- tenant does not compile. These policies are the second, and they exist for what
-- the compiler cannot see - a hand-written query, a migration, an ad-hoc join.
--
-- Every policy compares against current_setting('signet.tenant_id', true). The
-- second argument makes a missing setting yield NULL rather than raise, and a NULL
-- comparison is not true, so a connection that never set the variable sees no
-- tenant-owned rows at all. Forgetting it produces an empty result, never a
-- cross-tenant one.
--
-- Generated from packages/db/src/rls.ts, which is the reviewable source of these
-- predicates. rls.migration.test.ts asserts that every table named there is
-- covered by a policy created in this folder, so a new tenant-owned table cannot
-- ship without one.
alter table tenants enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on tenants;
--> statement-breakpoint
create policy signet_tenant_isolation on tenants for all using (id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table tenant_members enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on tenant_members;
--> statement-breakpoint
create policy signet_tenant_isolation on tenant_members for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table api_tokens enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on api_tokens;
--> statement-breakpoint
create policy signet_tenant_isolation on api_tokens for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table audit_events enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on audit_events;
--> statement-breakpoint
create policy signet_tenant_isolation on audit_events for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table endpoints enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on endpoints;
--> statement-breakpoint
create policy signet_tenant_isolation on endpoints for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table endpoint_keys enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on endpoint_keys;
--> statement-breakpoint
create policy signet_tenant_isolation on endpoint_keys for all using (exists (
    select 1 from endpoints e
    where e.id = endpoint_keys.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table idp_configs enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on idp_configs;
--> statement-breakpoint
create policy signet_tenant_isolation on idp_configs for all using (exists (
    select 1 from endpoints e
    where e.id = idp_configs.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table end_users enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on end_users;
--> statement-breakpoint
create policy signet_tenant_isolation on end_users for all using (exists (
    select 1 from endpoints e
    where e.id = end_users.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table clients enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on clients;
--> statement-breakpoint
create policy signet_tenant_isolation on clients for all using (exists (
    select 1 from endpoints e
    where e.id = clients.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table client_requests enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on client_requests;
--> statement-breakpoint
create policy signet_tenant_isolation on client_requests for all using (exists (
    select 1 from endpoints e
    where e.id = client_requests.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table policies enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on policies;
--> statement-breakpoint
create policy signet_tenant_isolation on policies for all using (exists (
    select 1 from endpoints e
    where e.id = policies.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table launch_contexts enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on launch_contexts;
--> statement-breakpoint
create policy signet_tenant_isolation on launch_contexts for all using (exists (
    select 1 from endpoints e
    where e.id = launch_contexts.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table authorization_sessions enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on authorization_sessions;
--> statement-breakpoint
create policy signet_tenant_isolation on authorization_sessions for all using (exists (
    select 1 from endpoints e
    where e.id = authorization_sessions.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table access_tokens enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on access_tokens;
--> statement-breakpoint
create policy signet_tenant_isolation on access_tokens for all using (exists (
    select 1 from endpoints e
    where e.id = access_tokens.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table refresh_tokens enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on refresh_tokens;
--> statement-breakpoint
create policy signet_tenant_isolation on refresh_tokens for all using (exists (
    select 1 from endpoints e
    where e.id = refresh_tokens.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table consents enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on consents;
--> statement-breakpoint
create policy signet_tenant_isolation on consents for all using (exists (
    select 1 from endpoints e
    where e.id = consents.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table end_user_sessions enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on end_user_sessions;
--> statement-breakpoint
create policy signet_tenant_isolation on end_user_sessions for all using (exists (
    select 1 from endpoints e
    where e.id = end_user_sessions.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table federation_states enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on federation_states;
--> statement-breakpoint
create policy signet_tenant_isolation on federation_states for all using (exists (
    select 1 from endpoints e
    where e.id = federation_states.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table client_policy_overrides enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on client_policy_overrides;
--> statement-breakpoint
create policy signet_tenant_isolation on client_policy_overrides for all using (exists (
    select 1
    from clients c
    join endpoints e on e.id = c.endpoint_id
    where c.id = client_policy_overrides.client_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table jti_replay enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on jti_replay;
--> statement-breakpoint
create policy signet_tenant_isolation on jti_replay for all using (exists (
    select 1
    from clients c
    join endpoints e on e.id = c.endpoint_id
    where c.id = jti_replay.client_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
alter table authorization_codes enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on authorization_codes;
--> statement-breakpoint
create policy signet_tenant_isolation on authorization_codes for all using (exists (
    select 1
    from authorization_sessions s
    join endpoints e on e.id = s.endpoint_id
    where s.id = authorization_codes.session_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
