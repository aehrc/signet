/**
 * Console sign-in and personal access tokens.
 *
 * Both credentials the admin API accepts are described here: the browser's
 * password-and-second-factor sign-in, and the bearer token a script presents. The
 * server holds neither in the clear, so nothing in this file has a response
 * counterpart carrying a secret - except the one moment a new personal access
 * token is shown to the person who minted it, which is the only time it exists
 * outside the caller's own storage.
 *
 * Author: John Grimes
 */

import { z } from "zod";

/**
 * A console sign-in.
 *
 * The TOTP code is optional in the schema and conditionally required by the
 * server: whether a second factor is needed depends on whether the account has
 * enrolled one, which the caller must not be told before authenticating.
 */
export const adminLoginSchema = z.object({
  email: z.string().min(3).max(320),
  password: z.string().min(1).max(1024),
  /** Six digits from an authenticator app. */
  totp: z
    .string()
    .regex(/^\d{6}$/, { message: "Must be six digits" })
    .optional(),
});

/** The roles a membership or personal access token may hold. */
export const tenantRoleSchema = z.enum([
  "viewer",
  "developer",
  "admin",
  "owner",
]);

/** Minting a personal access token. */
export const apiTokenCreateSchema = z.object({
  name: z.string().min(1).max(200),
  role: tenantRoleSchema,
  /**
   * Absent means a token that does not expire.
   *
   * Permitted, because a CI pipeline that stops working at an unpredictable
   * moment is worse than one whose token is deliberately long-lived and
   * revocable - but the console shows the difference plainly.
   */
  expiresAt: z.coerce.date().optional(),
});

/** Granting or changing a tenant membership. */
export const memberRoleSchema = z.object({
  email: z.string().min(3).max(320),
  role: tenantRoleSchema,
});

export type AdminLogin = z.infer<typeof adminLoginSchema>;
export type ApiTokenCreate = z.infer<typeof apiTokenCreateSchema>;
export type MemberRole = z.infer<typeof memberRoleSchema>;
export type TenantRoleValue = z.infer<typeof tenantRoleSchema>;
