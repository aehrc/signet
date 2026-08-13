/**
 * How an issuance refusal becomes a token endpoint response.
 *
 * Shared by all three grants, because the mapping is a judgement about *whose*
 * fault each failure is, and that judgement must not differ between grants.
 *
 * Two of the three are deliberately answered with a 500:
 *
 * - **No policy.** An endpoint with no published policy grants nothing. Answering
 *   400 would tell a correctly behaving app to discard its credential and try
 *   again, which will fail identically until an operator publishes a policy - and
 *   would send its developer looking for a bug in their own code.
 * - **No signing key.** The same reasoning. An endpoint whose only key has been
 *   retired cannot issue tokens until a new one is activated, and nothing the app
 *   does will change that.
 *
 * The third is a genuine 400: a policy that granted none of the requested scopes
 * has refused the request, and the app can act on it by asking for less.
 *
 * Author: John Grimes
 */

import { grantRefusal } from "./types.js";

import type { GrantOutcome } from "./types.js";
import type { IssuanceRefusal } from "../issuance.js";

/** Turns an issuance refusal into a token endpoint refusal. */
export function issuanceRefusalOutcome(reason: IssuanceRefusal): GrantOutcome {
  switch (reason) {
    case "vouching-expired": {
      // `invalid_client`, and therefore 401, for the same reason a suspended
      // registration gets one: the credential authenticated, but the registration
      // behind it is no longer one this endpoint honours. An app told
      // `invalid_grant` would retry with a fresh authorization and fail again;
      // told `invalid_client` it goes and gets registered again, which is exactly
      // what an expired vouching requires it to do.
      return grantRefusal(
        "invalid_client",
        "This client's vouching has expired, so it can no longer obtain tokens; register again with a current software statement",
        { reason: "vouching-expired" },
      );
    }
    case "no-policy": {
      return grantRefusal(
        "invalid_request",
        "This endpoint has no published policy, so it can issue no tokens",
        { misconfiguration: "no-policy" },
        500,
      );
    }
    case "no-signing-key": {
      return grantRefusal(
        "invalid_request",
        "This endpoint has no active signing key, so it can issue no tokens",
        { misconfiguration: "no-signing-key" },
        500,
      );
    }
    case "nothing-granted": {
      return grantRefusal(
        "invalid_scope",
        "The endpoint's policy granted none of the requested scopes",
      );
    }
    case "refresh-token-unusable": {
      // The `refresh_token` grant handles this itself, because only it knows
      // whether the refusal was a replay worth auditing as one. It is covered here
      // so that a grant which does not rotate a token cannot silently fall through
      // to a success path if one is ever given a `rotate` instruction by mistake.
      return grantRefusal("invalid_grant", "The refresh token is not valid", {
        reason: "refresh-token-unusable",
      });
    }
  }
}
