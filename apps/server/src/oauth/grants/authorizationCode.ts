/**
 * The `authorization_code` grant.
 *
 * Four checks stand between a code and a token, and each of them exists because
 * skipping it is a known attack:
 *
 * 1. **Single use.** The code is claimed by a conditional `UPDATE` in the data
 *    layer, so two concurrent redemptions produce one winner. A replayed code is
 *    reported as `already-consumed`, which RFC 6749 §10.5 says should be treated as
 *    an attack - Signet revokes every token issued from that authorization, because
 *    if two parties hold the code then one of them holds a token they should not.
 * 2. **Redirect URI binding.** The `redirect_uri` presented here must equal the one
 *    the code was issued against. Without it, an attacker who obtained a code can
 *    redeem it having never controlled the destination it was delivered to.
 * 3. **PKCE.** The verifier must hash to the challenge recorded at `/authorize`.
 *    This is what a public client has instead of a secret, and it is the only thing
 *    that makes a code intercepted from a mobile app's redirect useless.
 * 4. **Client identity.** The code's session belongs to one client. A different
 *    client presenting a valid code - including one that authenticated
 *    successfully as itself - must be refused.
 *
 * The scopes come from the session, not from the request. An app cannot ask for
 * more at the token endpoint than the user approved at the consent screen, because
 * there is nowhere in this handler that the request's `scope` parameter is read.
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
import { parseScopes, verifyPkce } from "@signet/core";
import {
  consumeAuthorizationCode,
  hashToken,
  revokeAccessTokensForClient,
  revokeRefreshTokensForClient,
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
import type { ConsumptionRefusal } from "@signet/db";
/* jscpd:ignore-end */

/** Why a presented code could not be claimed, in words a developer can act on. */
const CODE_REFUSAL_DESCRIPTIONS: Readonly<Record<ConsumptionRefusal, string>> =
  {
    "not-found": "The authorization code is not valid",
    "already-consumed": "The authorization code has already been used",
    expired: "The authorization code has expired",
  };

/**
 * Redeems an authorization code.
 *
 * @param context - The server's dependencies.
 * @param request - The authenticated client and the request body.
 */
export async function authorizationCodeGrant(
  context: ServerContext,
  request: GrantRequest,
): Promise<GrantOutcome> {
  const { issuerContext, authenticated, body } = request;
  const { scope, client } = authenticated;

  const code = formField(body, "code");
  if (code === undefined) {
    return grantRefusal("invalid_request", "code is required");
  }
  const redirectUri = formField(body, "redirect_uri");
  if (redirectUri === undefined) {
    return grantRefusal("invalid_request", "redirect_uri is required");
  }
  const verifier = formField(body, "code_verifier");
  if (verifier === undefined) {
    return grantRefusal(
      "invalid_request",
      "code_verifier is required; PKCE is mandatory",
    );
  }

  const redemption = await withTenantScope(
    context.db,
    issuerContext.scope,
    async (bound) => consumeAuthorizationCode(bound, await hashToken(code)),
  );

  if (!redemption.ok) {
    if (redemption.reason === "already-consumed") {
      // RFC 6749 §10.5: a replayed code means the code leaked. Revoking
      // everything the client holds is the only response that limits the damage,
      // and it is preferable to leaving a possibly-stolen token live for its full
      // lifetime.
      const accessRevoked = await withTenantScope(context.db, scope, (bound) =>
        revokeAccessTokensForClient(bound, context.clock()),
      );
      const refreshRevoked = await withTenantScope(context.db, scope, (bound) =>
        revokeRefreshTokensForClient(bound, context.clock()),
      );
      await recordReplayRevocation(context, request, {
        action: "token.revoked",
        target: "client",
        reason: "authorization-code-replay",
        revokedAccessCount: accessRevoked,
        revokedRefreshCount: refreshRevoked,
      });
    }
    return grantRefusal(
      "invalid_grant",
      CODE_REFUSAL_DESCRIPTIONS[redemption.reason],
      { codeRefusal: redemption.reason },
    );
  }

  const session = redemption.session;

  // The code has now been spent. Every remaining check therefore refuses without
  // any way for the client to retry, which is correct: a mismatched binding means
  // this is not the party the code was issued to.
  if (session.clientId !== scope.clientRowId) {
    return grantRefusal(
      "invalid_grant",
      "This authorization code was issued to a different client",
      { reason: "client-mismatch" },
    );
  }
  if (session.redirectUri !== redirectUri) {
    return grantRefusal(
      "invalid_grant",
      "redirect_uri does not match the one the code was issued for",
      { reason: "redirect-uri-mismatch" },
    );
  }

  if (session.codeChallenge === null || session.codeChallengeMethod === null) {
    // `/authorize` refuses a request without a challenge, so a session lacking
    // one cannot arise from a normal flow. Refusing is the safe reading: the
    // alternative is to issue a token for a code with no proof of possession.
    return grantRefusal(
      "invalid_grant",
      "This authorization recorded no PKCE challenge",
      { reason: "no-pkce-challenge" },
    );
  }

  const pkce = await verifyPkce(
    verifier,
    session.codeChallenge,
    session.codeChallengeMethod,
  );
  if (!pkce.ok) {
    return grantRefusal("invalid_grant", "The PKCE verifier does not match", {
      reason: `pkce-${pkce.code}`,
    });
  }

  if (session.endUserId === null) {
    // Only reachable if a code were issued for a session with no user, which the
    // interaction's step machine does not permit. Refusing rather than issuing a
    // token with no subject is the safe reading of an impossible state.
    return grantRefusal(
      "invalid_grant",
      "This authorization was never completed by a user",
      { reason: "no-user" },
    );
  }

  const resolved = await requireEndUser(
    context,
    issuerContext,
    session.endUserId,
  );
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
    grantType: "authorization_code",
    // From the session, never from the request body. See the module header.
    requested: parseScopes(session.requestedScopes.join(" ")).scopes,
    launchContext: session.resolvedContext ?? {},
    subject: user.id,
    ...(session.nonce === null ? {} : { nonce: session.nonce }),
    ...(session.consentGrantedAt === null
      ? {}
      : { authTime: Math.floor(session.consentGrantedAt.getTime() / 1000) }),
  });

  if (!issued.ok) {
    return issuanceRefusalOutcome(issued.reason);
  }

  await recordTokenIssued(
    context,
    request,
    "authorization_code",
    user.id,
    issued.issued,
  );

  return { ok: true, response: issued.issued.response };
}
