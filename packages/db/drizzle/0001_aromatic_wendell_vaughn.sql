-- Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
-- (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

CREATE TABLE "end_user_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"end_user_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"ip" text,
	"user_agent" text
);
--> statement-breakpoint
ALTER TABLE "client_requests" ADD COLUMN "tracking_token_hash" text;--> statement-breakpoint
ALTER TABLE "end_user_sessions" ADD CONSTRAINT "end_user_sessions_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "end_user_sessions" ADD CONSTRAINT "end_user_sessions_end_user_id_end_users_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."end_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "end_user_sessions_token_hash_unique" ON "end_user_sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "end_user_sessions_end_user_id_idx" ON "end_user_sessions" USING btree ("end_user_id");--> statement-breakpoint
CREATE INDEX "end_user_sessions_endpoint_id_idx" ON "end_user_sessions" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "end_user_sessions_expires_at_idx" ON "end_user_sessions" USING btree ("expires_at");