-- Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
-- (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.

CREATE TYPE "public"."audit_actor_type" AS ENUM('admin_user', 'api_token', 'end_user', 'client', 'system');--> statement-breakpoint
CREATE TYPE "public"."client_request_status" AS ENUM('pending', 'approved', 'rejected');--> statement-breakpoint
CREATE TYPE "public"."client_status" AS ENUM('pending', 'active', 'suspended', 'rejected');--> statement-breakpoint
CREATE TYPE "public"."client_type" AS ENUM('public', 'confidential-symmetric', 'confidential-asymmetric');--> statement-breakpoint
CREATE TYPE "public"."endpoint_auth_mode" AS ENUM('local', 'persona', 'oidc');--> statement-breakpoint
CREATE TYPE "public"."endpoint_consent_mode" AS ENUM('always', 'remember', 'auto');--> statement-breakpoint
CREATE TYPE "public"."endpoint_key_algorithm" AS ENUM('RS384', 'ES384');--> statement-breakpoint
CREATE TYPE "public"."endpoint_key_status" AS ENUM('active', 'next', 'retired');--> statement-breakpoint
CREATE TYPE "public"."endpoint_status" AS ENUM('active', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."grant_type" AS ENUM('authorization_code', 'client_credentials', 'refresh_token');--> statement-breakpoint
CREATE TYPE "public"."tenant_member_role" AS ENUM('owner', 'admin', 'developer', 'viewer');--> statement-breakpoint
CREATE TABLE "audit_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"endpoint_id" uuid,
	"actor_type" "audit_actor_type" NOT NULL,
	"actor_id" text,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip" text,
	"user_agent" text,
	"at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "client_requests" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"requested_by_email" text NOT NULL,
	"payload" jsonb NOT NULL,
	"status" "client_request_status" DEFAULT 'pending' NOT NULL,
	"reviewer_id" uuid,
	"decision_note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone,
	"resulting_client_id" uuid
);
--> statement-breakpoint
CREATE TABLE "clients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"client_id" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"logo_url" text,
	"client_type" "client_type" NOT NULL,
	"secret_hash" text,
	"secret_expires_at" timestamp with time zone,
	"jwks" jsonb,
	"jwks_uri" text,
	"jwks_cached_at" timestamp with time zone,
	"redirect_uris" text[] DEFAULT '{}' NOT NULL,
	"launch_uri" text,
	"grant_types" "grant_type"[] NOT NULL,
	"allowed_scopes" text[] DEFAULT '{}' NOT NULL,
	"status" "client_status" DEFAULT 'pending' NOT NULL,
	"contact_email" text,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "end_users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"username" text NOT NULL,
	"password_hash" text,
	"fhir_user_reference" text,
	"display_name" text NOT NULL,
	"roles" text[] DEFAULT '{}' NOT NULL,
	"attributes" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"default_context" jsonb,
	"is_persona" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"disabled_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "endpoint_keys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"kid" text NOT NULL,
	"algorithm" "endpoint_key_algorithm" NOT NULL,
	"public_jwk" jsonb NOT NULL,
	"private_jwk_encrypted" text NOT NULL,
	"status" "endpoint_key_status" DEFAULT 'next' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"activated_at" timestamp with time zone,
	"retired_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "endpoints" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"fhir_base_url" text NOT NULL,
	"supports_ehr_launch" boolean DEFAULT true NOT NULL,
	"supports_standalone_launch" boolean DEFAULT true NOT NULL,
	"supports_authorize_post" boolean DEFAULT false NOT NULL,
	"allows_public_clients" boolean DEFAULT true NOT NULL,
	"allows_confidential_symmetric_clients" boolean DEFAULT true NOT NULL,
	"allows_confidential_asymmetric_clients" boolean DEFAULT true NOT NULL,
	"supports_openid_connect" boolean DEFAULT true NOT NULL,
	"supports_patient_banner" boolean DEFAULT true NOT NULL,
	"supports_styling" boolean DEFAULT false NOT NULL,
	"supports_ehr_patient_context" boolean DEFAULT true NOT NULL,
	"supports_ehr_encounter_context" boolean DEFAULT true NOT NULL,
	"supports_standalone_patient_context" boolean DEFAULT true NOT NULL,
	"supports_standalone_encounter_context" boolean DEFAULT false NOT NULL,
	"supports_offline_access" boolean DEFAULT true NOT NULL,
	"supports_online_access" boolean DEFAULT true NOT NULL,
	"supports_patient_scopes" boolean DEFAULT true NOT NULL,
	"supports_user_scopes" boolean DEFAULT true NOT NULL,
	"supports_v1_scopes" boolean DEFAULT true NOT NULL,
	"supports_v2_scopes" boolean DEFAULT true NOT NULL,
	"supports_app_state" boolean DEFAULT false NOT NULL,
	"supports_backend_services" boolean DEFAULT true NOT NULL,
	"supports_dynamic_registration" boolean DEFAULT false NOT NULL,
	"scopes_supported" text[] DEFAULT '{}' NOT NULL,
	"user_access_brand_bundle" text,
	"user_access_brand_identifier" text,
	"access_token_ttl" integer DEFAULT 300 NOT NULL,
	"refresh_token_ttl" integer DEFAULT 2592000 NOT NULL,
	"auth_mode" "endpoint_auth_mode" DEFAULT 'local' NOT NULL,
	"consent_mode" "endpoint_consent_mode" DEFAULT 'always' NOT NULL,
	"is_production" boolean DEFAULT true NOT NULL,
	"status" "endpoint_status" DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "idp_configs" (
	"endpoint_id" uuid PRIMARY KEY NOT NULL,
	"issuer" text NOT NULL,
	"client_id" text NOT NULL,
	"client_secret_encrypted" text,
	"scopes" text[] DEFAULT '{"openid","profile"}' NOT NULL,
	"claim_mappings" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"discovery_cached_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "client_policy_overrides" (
	"client_id" uuid PRIMARY KEY NOT NULL,
	"document" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "policies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"version" integer NOT NULL,
	"document" jsonb NOT NULL,
	"published" boolean DEFAULT false NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"note" text
);
--> statement-breakpoint
CREATE TABLE "access_tokens" (
	"jti" text PRIMARY KEY NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"subject" text NOT NULL,
	"scope" text NOT NULL,
	"issuer" text NOT NULL,
	"audience" text NOT NULL,
	"launch_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"id_token_claims" jsonb,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "authorization_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code_hash" text NOT NULL,
	"session_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "authorization_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"requested_scopes" text[] DEFAULT '{}' NOT NULL,
	"redirect_uri" text NOT NULL,
	"state" text,
	"code_challenge" text,
	"code_challenge_method" text,
	"aud" text,
	"nonce" text,
	"launch_context_id" uuid,
	"end_user_id" uuid,
	"resolved_context" jsonb,
	"consent_granted_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "consents" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"end_user_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"scope" text NOT NULL,
	"granted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "jti_replay" (
	"client_id" uuid NOT NULL,
	"jti" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "jti_replay_pk" PRIMARY KEY("client_id","jti")
);
--> statement-breakpoint
CREATE TABLE "launch_contexts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"handle_hash" text NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"client_id" uuid,
	"context" jsonb NOT NULL,
	"created_by" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "refresh_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token_hash" text NOT NULL,
	"family_id" uuid NOT NULL,
	"endpoint_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"subject" text NOT NULL,
	"scope" text NOT NULL,
	"launch_context" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"replaced_by_id" uuid
);
--> statement-breakpoint
CREATE TABLE "admin_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"token_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"revoked_at" timestamp with time zone,
	"ip" text,
	"user_agent" text
);
--> statement-breakpoint
CREATE TABLE "admin_users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"password_hash" text NOT NULL,
	"totp_secret_encrypted" text,
	"display_name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_login_at" timestamp with time zone,
	"disabled_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "api_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL,
	"role" "tenant_member_role" NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "tenant_members" (
	"tenant_id" uuid NOT NULL,
	"admin_user_id" uuid NOT NULL,
	"role" "tenant_member_role" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_members_pk" PRIMARY KEY("tenant_id","admin_user_id")
);
--> statement-breakpoint
CREATE TABLE "tenants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"slug" text NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_requests" ADD CONSTRAINT "client_requests_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_requests" ADD CONSTRAINT "client_requests_reviewer_id_admin_users_id_fk" FOREIGN KEY ("reviewer_id") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_requests" ADD CONSTRAINT "client_requests_resulting_client_id_clients_id_fk" FOREIGN KEY ("resulting_client_id") REFERENCES "public"."clients"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "clients" ADD CONSTRAINT "clients_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "clients" ADD CONSTRAINT "clients_created_by_admin_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "end_users" ADD CONSTRAINT "end_users_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "endpoint_keys" ADD CONSTRAINT "endpoint_keys_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "endpoints" ADD CONSTRAINT "endpoints_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "idp_configs" ADD CONSTRAINT "idp_configs_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "client_policy_overrides" ADD CONSTRAINT "client_policy_overrides_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "policies" ADD CONSTRAINT "policies_created_by_admin_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_tokens" ADD CONSTRAINT "access_tokens_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "access_tokens" ADD CONSTRAINT "access_tokens_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_session_id_authorization_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."authorization_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_launch_context_id_launch_contexts_id_fk" FOREIGN KEY ("launch_context_id") REFERENCES "public"."launch_contexts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_end_user_id_end_users_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."end_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "consents" ADD CONSTRAINT "consents_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "consents" ADD CONSTRAINT "consents_end_user_id_end_users_id_fk" FOREIGN KEY ("end_user_id") REFERENCES "public"."end_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "consents" ADD CONSTRAINT "consents_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "jti_replay" ADD CONSTRAINT "jti_replay_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "launch_contexts" ADD CONSTRAINT "launch_contexts_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "launch_contexts" ADD CONSTRAINT "launch_contexts_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_endpoint_id_endpoints_id_fk" FOREIGN KEY ("endpoint_id") REFERENCES "public"."endpoints"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_client_id_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_replaced_by_id_refresh_tokens_id_fk" FOREIGN KEY ("replaced_by_id") REFERENCES "public"."refresh_tokens"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "admin_sessions" ADD CONSTRAINT "admin_sessions_admin_user_id_admin_users_id_fk" FOREIGN KEY ("admin_user_id") REFERENCES "public"."admin_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "api_tokens" ADD CONSTRAINT "api_tokens_created_by_admin_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."admin_users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_members" ADD CONSTRAINT "tenant_members_admin_user_id_admin_users_id_fk" FOREIGN KEY ("admin_user_id") REFERENCES "public"."admin_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_events_tenant_id_at_idx" ON "audit_events" USING btree ("tenant_id","at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_events_endpoint_id_at_idx" ON "audit_events" USING btree ("endpoint_id","at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "audit_events_action_idx" ON "audit_events" USING btree ("action");--> statement-breakpoint
CREATE INDEX "audit_events_target_idx" ON "audit_events" USING btree ("target_type","target_id");--> statement-breakpoint
CREATE INDEX "audit_events_actor_idx" ON "audit_events" USING btree ("actor_type","actor_id");--> statement-breakpoint
CREATE INDEX "client_requests_endpoint_id_status_idx" ON "client_requests" USING btree ("endpoint_id","status");--> statement-breakpoint
CREATE INDEX "client_requests_reviewer_id_idx" ON "client_requests" USING btree ("reviewer_id");--> statement-breakpoint
CREATE INDEX "client_requests_resulting_client_id_idx" ON "client_requests" USING btree ("resulting_client_id");--> statement-breakpoint
CREATE UNIQUE INDEX "clients_client_id_unique" ON "clients" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "clients_endpoint_id_idx" ON "clients" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "clients_created_by_idx" ON "clients" USING btree ("created_by");--> statement-breakpoint
CREATE UNIQUE INDEX "end_users_endpoint_id_username_unique" ON "end_users" USING btree ("endpoint_id","username");--> statement-breakpoint
CREATE INDEX "end_users_endpoint_id_idx" ON "end_users" USING btree ("endpoint_id");--> statement-breakpoint
CREATE UNIQUE INDEX "endpoint_keys_endpoint_id_kid_unique" ON "endpoint_keys" USING btree ("endpoint_id","kid");--> statement-breakpoint
CREATE INDEX "endpoint_keys_endpoint_id_status_idx" ON "endpoint_keys" USING btree ("endpoint_id","status");--> statement-breakpoint
CREATE UNIQUE INDEX "endpoints_tenant_id_slug_unique" ON "endpoints" USING btree ("tenant_id","slug");--> statement-breakpoint
CREATE INDEX "endpoints_tenant_id_idx" ON "endpoints" USING btree ("tenant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "policies_endpoint_id_version_unique" ON "policies" USING btree ("endpoint_id","version");--> statement-breakpoint
CREATE UNIQUE INDEX "policies_one_published_per_endpoint" ON "policies" USING btree ("endpoint_id") WHERE "policies"."published";--> statement-breakpoint
CREATE INDEX "policies_endpoint_id_idx" ON "policies" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "policies_created_by_idx" ON "policies" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "access_tokens_endpoint_id_idx" ON "access_tokens" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "access_tokens_client_id_idx" ON "access_tokens" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "access_tokens_subject_idx" ON "access_tokens" USING btree ("subject");--> statement-breakpoint
CREATE INDEX "access_tokens_expires_at_idx" ON "access_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "authorization_codes_code_hash_unique" ON "authorization_codes" USING btree ("code_hash");--> statement-breakpoint
CREATE INDEX "authorization_codes_session_id_idx" ON "authorization_codes" USING btree ("session_id");--> statement-breakpoint
CREATE INDEX "authorization_codes_expires_at_idx" ON "authorization_codes" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "authorization_sessions_endpoint_id_idx" ON "authorization_sessions" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "authorization_sessions_client_id_idx" ON "authorization_sessions" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "authorization_sessions_launch_context_id_idx" ON "authorization_sessions" USING btree ("launch_context_id");--> statement-breakpoint
CREATE INDEX "authorization_sessions_end_user_id_idx" ON "authorization_sessions" USING btree ("end_user_id");--> statement-breakpoint
CREATE INDEX "authorization_sessions_expires_at_idx" ON "authorization_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "consents_end_user_id_client_id_idx" ON "consents" USING btree ("end_user_id","client_id");--> statement-breakpoint
CREATE INDEX "consents_endpoint_id_idx" ON "consents" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "consents_client_id_idx" ON "consents" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "consents_expires_at_idx" ON "consents" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "jti_replay_expires_at_idx" ON "jti_replay" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "launch_contexts_handle_hash_unique" ON "launch_contexts" USING btree ("handle_hash");--> statement-breakpoint
CREATE INDEX "launch_contexts_endpoint_id_idx" ON "launch_contexts" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "launch_contexts_client_id_idx" ON "launch_contexts" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "launch_contexts_expires_at_idx" ON "launch_contexts" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "refresh_tokens_token_hash_unique" ON "refresh_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "refresh_tokens_family_id_idx" ON "refresh_tokens" USING btree ("family_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_endpoint_id_idx" ON "refresh_tokens" USING btree ("endpoint_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_client_id_idx" ON "refresh_tokens" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_replaced_by_id_idx" ON "refresh_tokens" USING btree ("replaced_by_id");--> statement-breakpoint
CREATE INDEX "refresh_tokens_expires_at_idx" ON "refresh_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "admin_sessions_token_hash_unique" ON "admin_sessions" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "admin_sessions_admin_user_id_idx" ON "admin_sessions" USING btree ("admin_user_id");--> statement-breakpoint
CREATE INDEX "admin_sessions_expires_at_idx" ON "admin_sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "admin_users_email_unique" ON "admin_users" USING btree (lower("email"));--> statement-breakpoint
CREATE UNIQUE INDEX "api_tokens_token_hash_unique" ON "api_tokens" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "api_tokens_tenant_id_idx" ON "api_tokens" USING btree ("tenant_id");--> statement-breakpoint
CREATE INDEX "api_tokens_created_by_idx" ON "api_tokens" USING btree ("created_by");--> statement-breakpoint
CREATE INDEX "api_tokens_expires_at_idx" ON "api_tokens" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "tenant_members_admin_user_id_idx" ON "tenant_members" USING btree ("admin_user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "tenants_slug_unique" ON "tenants" USING btree ("slug");