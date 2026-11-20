-- Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
-- (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

-- End users move from the endpoint to the tenant, so one person holds one account,
-- one username and one password across the tenant's endpoints. Access to each
-- endpoint becomes an explicit row in end_user_endpoints, which also carries what
-- only means something on one endpoint: the fhirUser reference and a persona's
-- default launch context.
--
-- Every existing account keeps its id, so consents, tokens and the audit trail still
-- name it, and is given access to the endpoint it belonged to. Two endpoints of one
-- tenant may each have had an account with the same username; the oldest keeps it
-- and each later one is renamed to username@endpoint-slug. Nothing is merged, since
-- the two accounts may have different passwords and may be different people.
CREATE TABLE "end_user_endpoints" (
	"end_user_id" uuid NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"fhir_user_reference" text,
	"default_context" jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "end_user_endpoints_pk" PRIMARY KEY("end_user_id","endpoint_id")
);
--> statement-breakpoint
ALTER TABLE "end_user_endpoints" ADD CONSTRAINT "end_user_endpoints_end_user_id_end_users_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."end_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "end_user_endpoints" ADD CONSTRAINT "end_user_endpoints_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "end_user_endpoints_endpoint_id_idx" ON "end_user_endpoints" USING btree ("endpoint_id");--> statement-breakpoint
INSERT INTO "end_user_endpoints" ("end_user_id", "endpoint_id", "fhir_user_reference", "default_context", "created_at")
	SELECT "id", "endpoint_id", "fhir_user_reference", "default_context", "created_at" FROM "end_users";--> statement-breakpoint
ALTER TABLE "end_users" ADD COLUMN "tenant_id" uuid;--> statement-breakpoint
UPDATE "end_users" SET "tenant_id" = e."tenant_id" FROM "endpoints" e WHERE e."id" = "end_users"."endpoint_id";--> statement-breakpoint
-- Ranked by creation, then by id so that a tie is still resolved the same way every
-- time. The subquery reads the rows as they were before this statement, so a rename
-- cannot change which row ranks first.
UPDATE "end_users" SET "username" = "end_users"."username" || '@' || e."slug"
	FROM (
		SELECT "id", row_number() OVER (PARTITION BY "tenant_id", "username" ORDER BY "created_at", "id") AS "position"
		FROM "end_users"
	) ranked, "endpoints" e
	WHERE ranked."id" = "end_users"."id" AND ranked."position" > 1 AND e."id" = "end_users"."endpoint_id";--> statement-breakpoint
ALTER TABLE "end_users" ALTER COLUMN "tenant_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "end_users" ADD CONSTRAINT "end_users_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "end_user_invitations" ADD COLUMN "tenant_id" uuid;--> statement-breakpoint
UPDATE "end_user_invitations" SET "tenant_id" = e."tenant_id" FROM "endpoints" e WHERE e."id" = "end_user_invitations"."endpoint_id";--> statement-breakpoint
ALTER TABLE "end_user_invitations" ALTER COLUMN "tenant_id" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "end_user_invitations" ADD CONSTRAINT "end_user_invitations_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
-- Tenant isolation. The two existing policies read endpoint_id, which is about to be
-- dropped, so they are replaced first; the new table gets its policy in the migration
-- that creates it. Generated from packages/db/src/rls.ts, which is the reviewable
-- source of these predicates.
drop policy if exists signet_tenant_isolation on end_users;
--> statement-breakpoint
create policy signet_tenant_isolation on end_users for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on end_user_invitations;
--> statement-breakpoint
create policy signet_tenant_isolation on end_user_invitations for all using (tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid);
--> statement-breakpoint
alter table end_user_endpoints enable row level security;
--> statement-breakpoint
drop policy if exists signet_tenant_isolation on end_user_endpoints;
--> statement-breakpoint
create policy signet_tenant_isolation on end_user_endpoints for all using (exists (
    select 1 from endpoints e
    where e.id = end_user_endpoints.endpoint_id
      and e.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ) and exists (
    select 1 from end_users u
    where u.id = end_user_endpoints.end_user_id
      and u.tenant_id = nullif(current_setting('signet.tenant_id', true), '')::uuid
  ));
--> statement-breakpoint
ALTER TABLE "end_users" DROP CONSTRAINT "end_users_endpoint_id_endpoints_id_fk";--> statement-breakpoint
ALTER TABLE "end_user_invitations" DROP CONSTRAINT "end_user_invitations_endpoint_id_endpoints_id_fk";--> statement-breakpoint
DROP INDEX "end_users_endpoint_id_username_unique";--> statement-breakpoint
DROP INDEX "end_users_endpoint_id_idx";--> statement-breakpoint
DROP INDEX "end_user_invitations_endpoint_id_idx";--> statement-breakpoint
ALTER TABLE "end_users" DROP COLUMN "endpoint_id";--> statement-breakpoint
ALTER TABLE "end_users" DROP COLUMN "fhir_user_reference";--> statement-breakpoint
ALTER TABLE "end_users" DROP COLUMN "default_context";--> statement-breakpoint
ALTER TABLE "end_user_invitations" DROP COLUMN "endpoint_id";--> statement-breakpoint
CREATE UNIQUE INDEX "end_users_tenant_id_username_unique" ON "end_users" USING btree ("tenant_id","username");--> statement-breakpoint
CREATE INDEX "end_users_tenant_id_idx" ON "end_users" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "end_user_invitations_tenant_id_idx" ON "end_user_invitations" USING btree ("tenant_id");--> statement-breakpoint
-- Consents, management sessions and in-flight authorizations hang off the access
-- row, so withdrawing an account's access to one endpoint takes them with it. Every
-- existing row names the account's own endpoint, which is the access row backfilled
-- above.
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_end_user_endpoint_fk" FOREIGN KEY ("end_user_id","endpoint_id") REFERENCES "public"."end_user_endpoints"("end_user_id","endpoint_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "consents" ADD CONSTRAINT "consents_end_user_endpoint_fk" FOREIGN KEY ("end_user_id","endpoint_id") REFERENCES "public"."end_user_endpoints"("end_user_id","endpoint_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "end_user_sessions" ADD CONSTRAINT "end_user_sessions_end_user_endpoint_fk" FOREIGN KEY ("end_user_id","endpoint_id") REFERENCES "public"."end_user_endpoints"("end_user_id","endpoint_id") ON DELETE cascade ON UPDATE no action;
