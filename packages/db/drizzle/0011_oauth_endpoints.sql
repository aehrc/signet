-- Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
-- (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

-- A second kind of endpoint: a plain OAuth 2.0 / OpenID Connect issuer for an API
-- that is not a FHIR server, beside the SMART on FHIR issuer every existing
-- endpoint already is.
CREATE TYPE "public"."endpoint_kind" AS ENUM('smart', 'oauth');--> statement-breakpoint
-- Every existing endpoint is SMART on FHIR. The default exists only to backfill
-- those rows and is dropped straight away, so every later insert has to name its
-- kind rather than quietly becoming SMART.
ALTER TABLE "endpoints" ADD COLUMN "kind" "endpoint_kind" DEFAULT 'smart' NOT NULL;--> statement-breakpoint
ALTER TABLE "endpoints" ALTER COLUMN "kind" DROP DEFAULT;--> statement-breakpoint
-- The FHIR base URL was always the token audience; on an OAuth endpoint there is
-- no FHIR server, only the audience. Renamed in place, so no value moves.
ALTER TABLE "endpoints" RENAME COLUMN "fhir_base_url" TO "audience";--> statement-breakpoint
-- Policy templates name the same value. A template still reading the old name
-- would resolve to nothing and silently drop its claim, so stored documents are
-- rewritten along with the column.
UPDATE "policies" SET "document" = replace("document"::text, 'endpoint.fhirBaseUrl', 'endpoint.audience')::jsonb WHERE "document"::text LIKE '%endpoint.fhirBaseUrl%';--> statement-breakpoint
UPDATE "client_policy_overrides" SET "document" = replace("document"::text, 'endpoint.fhirBaseUrl', 'endpoint.audience')::jsonb WHERE "document"::text LIKE '%endpoint.fhirBaseUrl%';--> statement-breakpoint
ALTER TABLE "end_users" ADD COLUMN "email" text;--> statement-breakpoint
ALTER TABLE "end_users" ADD COLUMN "email_verified" boolean DEFAULT false NOT NULL;
