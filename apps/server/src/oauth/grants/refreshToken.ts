/**
 * The `refresh_token` grant, with rotation and reuse detection.
 *
 * Every redemption issues a new refresh token and revokes the one presented, in a
 * single transaction inside `../issuance.ts`. That is not merely hygiene: it is what
 * makes theft *detectable*. A stolen refresh token is indistinguishable from the
 * legitimate one until somebody presents a token that has already been rotated - at
 * which point two parties hold it, one of them should not, and the whole rotation
 * family is revoked. The data layer does the detection; this handler's job is to
 * react to it, which means auditing it distinctly and refusing without hinting at
 * which party was the impostor.
 *
 * Scopes may narrow but never widen. The presented token carries the scopes it was
 * issued with, and a `scope` parameter on the request can only ask for a subset of
 * them. Without that rule a refresh token would be an escalation primitive: obtain
 * one for `patient/Observation.rs` and refresh it into `patient/*.cruds`.
 *
 * The launch context is carried forward from the refreshed token rather than
 * re-resolved. The user is not present at a refresh, so there is nobody to pick a
 * patient - and a refresh that silently changed the patient in context would change
 * what the app is looking at without anybody having agreed to it.
 *
 * Every check that does *not* need the token to be spent happens before it is: the
 * row is read without claiming, and a client mismatch or a widened scope refuses
 * without logging the user out. A client bug should not cost the user their session.
 *
 * Author: John Grimes
 */

/* jscpd:ignore-start */
// The import list and the issuance call below are near-identical to the other
// interactive grant's, and deliberately so: both establish the same four things for
// `issueTokens`, and the parts that differ - the grant type, where the scopes came
// from, and which launch context applies - are exactly what a reader compares. The
// shared judgements have already been factored out into `./subject.ts`, `./audit.ts`
// and `./issuanceRefusals.ts`; what remains is the call itself.
import { areScopesCoveredBy, parseScopes } from "@signet/core";
import {
  findRefreshToken,
  hashToken,
  isLive,
  revokeAccessTokensForClient,
  toEvaluationClient,
  toEvaluationUser,
  withTenantScope,
} from "@signet/db";

import { recordReplayRevocation, recordTokenIssued } from "./audit.js";
import { issuanceRefusalOutcome } from "./issuanceRefusals.js";
import { requireEndUser } from "./subject.js";
import { issueTokens } from "../issuance.js";
import { formField, grantRefusal } from "./types.js";

import type { GrantOutcome, GrantRequest } from "./types.js";
import type { ServerContext } from "../../context.js";
import type { RefreshTokenRefusal } from "@signet/db";
/* jscpd:ignore-end */

/**
 * Why a presented refresh token was refused.
 *
 * Reuse gets the same message as an unknown token. Saying that it had already been
 * rotated would tell an attacker that the legitimate client is still active, and
 * telling the legitimate client that it has been robbed is not something a token
 * endpoint response can usefully do - that belongs in the audit trail, and in an
 * alert for a deployment that wants one.
 */
const REFRESH_REFUSAL_DESCRIPTIONS: Readonly<
  Record<RefreshTokenRefusal, string>
> = {
  "not-found": "The refresh token is not valid",
  reused: "The refresh token is not valid",
  revoked: "The refresh token has been revoked",
  expired: "The refresh token has expired",
};

/**
 * Refreshes an access token.
 *
 * @param context - The server's dependencies.
 * @param request - The authenticated client and the request body.
 */
export async function refreshTokenGrant(
  context: ServerContext,
  request: GrantRequest,
): Promise<GrantOutcome> {
  const { issuerContext, authenticated, body } = request;
  const { scope, client } = authenticated;

  if (!client.grantTypes.includes("refresh_token")) {
    return grantRefusal(
      "unauthorized_client",
      "This client is not registered for the refresh_token grant",
    );
  }

  const presented = formField(body, "refresh_token");
  if (presented === undefined) {
    return grantRefusal("invalid_request", "refresh_token is required");
  }
  const tokenHash = await hashToken(presented);

  // Read without claiming. Everything below this point up to the issuance is a
  // check that must not spend the token if it fails.
  const held = await withTenantScope(context.db, issuerContext.scope, (bound) =>
    findRefreshToken(bound, tokenHash),
  );
  if (held === undefined) {
    return grantRefusal(
      "invalid_grant",
      REFRESH_REFUSAL_DESCRIPTIONS["not-found"],
      { refreshRefusal: "not-found" },
    );
  }

  // A different client presenting somebody else's token is refused without the
  // token being spent: the rightful owner has done nothing wrong, and the presenter
  // has gained nothing they could use.
  if (held.clientId !== scope.clientRowId) {
    return grantRefusal("invalid_grant", "The refresh token is not valid", {
      reason: "client-mismatch",
    });
  }

  // Reuse is deliberately *not* short-circuited here. A token with a successor
  // fails `isLive`, and the claim inside the issuance is what detects the reuse and
  // revokes the family - doing it from this non-claiming read would race with a
  // concurrent legitimate refresh.
  if (!isLive(held, context.clock()) && held.replacedById === null) {
    return grantRefusal(
      "invalid_grant",
      REFRESH_REFUSAL_DESCRIPTIONS[
        held.revokedAt === null ? "expired" : "revoked"
      ],
      { refreshRefusal: held.revokedAt === null ? "expired" : "revoked" },
    );
  }

  const grantedPreviously = parseScopes(held.scope).scopes;
  const raw = formField(body, "scope");
  let requested = grantedPreviously;
  if (raw !== undefined) {
    const parsed = parseScopes(raw);
    const firstRejected = parsed.rejected[0];
    if (firstRejected !== undefined) {
      return grantRefusal(
        "invalid_scope",
        `Could not parse scope "${firstRejected.raw}": ${firstRejected.message}`,
      );
    }
    if (!areScopesCoveredBy(parsed.scopes, grantedPreviously)) {
      return grantRefusal(
        "invalid_scope",
        "A refresh may narrow the granted scopes but not widen them",
      );
    }
    requested = parsed.scopes;
  }

  // A refresh token is only ever issued for an interactive authorization, so its
  // subject is an end user id. One that no longer resolves means the user was
  // deleted since.
  /* jscpd:ignore-start */
  const resolved = await requireEndUser(context, issuerContext, held.subject);
  if (!resolved.ok) {
    return resolved.outcome;
  }
  const user = resolved.user;

  const issued = await issueTokens(context, {
    issuerContext,
    clientScope: scope,
    client: toEvaluationClient(client),
    user: toEvaluationUser(user),
    /* jscpd:ignore-end */
    grantType: "refresh_token",
    requested,
    launchContext: held.launchContext,
    subject: held.subject,
    rotate: { tokenHash },
  });

  if (!issued.ok) {
    if (issued.reason !== "refresh-token-unusable") {
      return issuanceRefusalOutcome(issued.reason);
    }

    if (issued.refresh === "reused") {
      // The family has already been revoked by the data layer. Revoking the
      // client's live access tokens as well is this handler's decision: they are
      // short-lived, but a replayed refresh token means one of them may be in the
      // wrong hands right now.
      const accessRevoked = await withTenantScope(context.db, scope, (bound) =>
        revokeAccessTokensForClient(bound, context.clock()),
      );
      await recordReplayRevocation(context, request, {
        action: "token.refresh-reuse-detected",
        target: "refresh-token",
        revokedAccessCount: accessRevoked,
        revokedRefreshCount: issued.familyRevoked,
      });
    }

    return grantRefusal(
      "invalid_grant",
      REFRESH_REFUSAL_DESCRIPTIONS[issued.refresh],
      { refreshRefusal: issued.refresh },
    );
  }

  await recordTokenIssued(
    context,
    request,
    "refresh_token",
    held.subject,
    issued.issued,
  );

  return { ok: true, response: issued.issued.response };
}
