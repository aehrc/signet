/**
 * Resolving the end user behind an interactive grant.
 *
 * Both interactive grants reach the same question from different directions - the
 * code grant holds a subject from its session, the refresh grant one from the token
 * it claimed - and must answer it the same way. A subject that no longer resolves
 * means the account was deleted since the authorization, and the right answer is to
 * refuse rather than to mint a token for a user who is gone.
 *
 * Author: John Grimes
 */

import { getEndUser, withTenantScope } from "@signet/db";

import { grantRefusal } from "./types.js";

import type { GrantOutcome } from "./types.js";
import type { ResolvedIssuerContext, ServerContext } from "../../context.js";
import type { EndUser } from "@signet/db";

/** The user, or the refusal to answer the token request with. */
export type EndUserResolution =
  | { readonly ok: true; readonly user: EndUser }
  | { readonly ok: false; readonly outcome: GrantOutcome };

/**
 * Resolves the end user a grant is about.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the grant is on.
 * @param subject - The `sub` the authorization recorded.
 */
export async function requireEndUser(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  subject: string,
): Promise<EndUserResolution> {
  const user = await withTenantScope(context.db, issuerContext.scope, (bound) =>
    getEndUser(bound, subject),
  );
  return user === undefined
    ? {
        ok: false,
        outcome: grantRefusal(
          "invalid_grant",
          "The user this authorization belongs to no longer exists",
          { reason: "user-deleted" },
        ),
      }
    : { ok: true, user };
}
