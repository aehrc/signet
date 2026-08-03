CREATE TABLE "federation_states" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"state_hash" text NOT NULL,
	"nonce" text NOT NULL,
	"code_verifier" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "federation_states" ADD CONSTRAINT "federation_states_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "federation_states" ADD CONSTRAINT "federation_states_session_id_authorization_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."authorization_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "federation_states_state_hash_unique" ON "federation_states" USING btree ("state_hash");--> statement-breakpoint
CREATE INDEX "federation_states_session_id_idx" ON "federation_states" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "federation_states_endpoint_id_idx" ON "federation_states" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "federation_states_expires_at_idx" ON "federation_states" USING btree ("expires_at");