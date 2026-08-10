/**
 * Registering, listing, removing and signing in with a passkey.
 *
 * Six routes, and the shape of the feature is in how they are paired. Each ceremony
 * takes two requests: one that mints a challenge and one that spends it. Everything
 * that decides whether the ceremony is allowed to happen at all is checked at the
 * first - the password, the ten-per-account cap - so the second has only the
 * cryptography left to judge. That is why the verify routes ask for no password: the
 * challenge they consume could only have been minted by somebody who supplied one,
 * and asking twice for the same decision would spend a user gesture on a request
 * that was already doomed or already allowed.
 *
 * **What refuses, and how loudly.** The management routes are behind a session and
 * may say plainly what went wrong: a wrong password carries a flag the dialog acts
 * on. The sign-in routes are unauthenticated and say nothing at all - an unknown
 * credential, a disabled account, a replayed challenge, a counter that suggests a
 * clone and a signature that does not verify are one sentence, the same sentence the
 * password sign-in gives. The distinction lives in the audit trail, which is where a
 * person who is entitled to it can read it.
 *
 * **The relying party is the deployment's public URL**, never a request header. A
 * Host-derived RP ID would let a misrouted request bind credentials to an identity
 * the operator did not choose, and the origin check in `clientDataJSON` is the whole
 * of the phishing resistance a passkey buys - it is worth exactly what the value it
 * is compared against is worth.
 *
 * Author: John Grimes
 */

import {
  passkeyAuthenticationSchema,
  passkeyPasswordSchema,
  passkeyRegistrationSchema,
} from "@signet/contracts";
import {
  decidePasskeySignIn,
  MAX_PASSKEYS_PER_ACCOUNT,
  passkeyCapReached,
  passkeyName,
  PASSKEY_CHALLENGE_TTL_SECONDS,
} from "@signet/core";
import {
  consumeAdminPasskeyChallenge,
  createAdminPasskeyChallenge,
  findAdminPasskeyByCredentialId,
  insertAdminPasskey,
  listAdminPasskeys,
  recordAdminPasskeyUse,
  removeAdminPasskey,
  verifyPassword,
} from "@signet/db";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";

import { adminErrorBody, statusForAdminError } from "./errors.js";
import { parseBody } from "./requestBody.js";
import {
  establishAdminSession,
  recordAuthenticationEvent,
  refuseSignIn,
} from "./session.js";
import { passkeyView } from "./views.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { AdminPrincipal, AdminUserPrincipal } from "./principal.js";
import type { ServerContext, SignetEnvironment } from "../context.js";
import type { AdminPasskeyChallenge, AdminUser } from "@signet/db";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { Context } from "hono";

/** How the browser is told to identify this deployment. */
interface RelyingParty {
  /** The RP ID: the hostname credentials are scoped to. */
  readonly id: string;
  /** The origin a ceremony must have been performed on. */
  readonly origin: string;
  /** What the browser shows the person during the prompt. */
  readonly name: string;
}

/**
 * The relying party, derived from the deployment's public URL and nothing else.
 *
 * `publicUrl` is already the source of truth for whether the session cookie is
 * marked `Secure`, so a passkey bound to a different identity than the cookie is not
 * a state this deployment can reach.
 */
function relyingParty(publicUrl: string): RelyingParty {
  const url = new URL(publicUrl);
  return { id: url.hostname, origin: url.origin, name: "Signet" };
}

/** Answers an admin API refusal. */
function refuse(
  c: Context<SignetEnvironment>,
  code: Parameters<typeof adminErrorBody>[0],
  message: string,
) {
  return c.json(adminErrorBody(code, message), statusForAdminError(code));
}

/**
 * Narrows the caller to a person, or answers 403.
 *
 * A personal access token is refused on every one of these routes. A token is not
 * the account owner, holds no password to confirm with, and belongs to one tenant
 * while a passkey belongs to a person - so there is nothing coherent for it to do
 * here, and the safe answer to "nothing coherent" is no.
 */
function requirePerson(
  c: Context<SignetEnvironment>,
): AdminUserPrincipal | Response {
  const principal: AdminPrincipal = c.get("principal");
  if (principal.kind !== "admin-user") {
    return refuse(
      c,
      "forbidden",
      "Passkeys are managed by the person who owns the account, in a browser session",
    );
  }
  return principal;
}

/** The refusal a wrong password gets, flagged so the dialog can say which it was. */
function refusePassword(c: Context<SignetEnvironment>) {
  return c.json(
    {
      ...adminErrorBody("unauthenticated", "That password was not accepted"),
      passwordRejected: true,
    },
    statusForAdminError("unauthenticated"),
  );
}

/**
 * The caller, once they have re-entered their password.
 *
 * Both operations that change the passkey list begin this way, and sharing the
 * preamble is what keeps them from drifting: a route that checked the principal but
 * forgot the password, or checked the password after doing the work, would look
 * almost identical to this and be a different thing entirely.
 *
 * @param c - The request being answered.
 * @returns The signed-in person, or the response to refuse with.
 */
async function personWithPassword(
  c: Context<SignetEnvironment>,
): Promise<AdminUserPrincipal | Response> {
  const principal = requirePerson(c);
  if (principal instanceof Response) {
    return principal;
  }
  const body = await parseBody(c, passkeyPasswordSchema);
  if (body instanceof Response) {
    return body;
  }
  if (!(await verifyPassword(body.password, principal.user.passwordHash))) {
    return refusePassword(c);
  }
  return principal;
}

/** When a challenge minted now stops being valid. */
function challengeExpiry(context: ServerContext): Date {
  return new Date(
    context.clock().getTime() + PASSKEY_CHALLENGE_TTL_SECONDS * 1000,
  );
}

/**
 * Handles `GET /api/v1/account/passkeys`: the caller's own passkeys.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeyListHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal = requirePerson(c);
    if (principal instanceof Response) {
      return principal;
    }

    const passkeys = await listAdminPasskeys(context.db, principal.user.id);
    return c.json({ passkeys: passkeys.map(passkeyView) });
  };
}

/**
 * Handles `POST /api/v1/account/passkeys/options`: begins a registration.
 *
 * The password is checked and the cap tested before a challenge is minted, so a
 * refused request leaves no row behind and no browser prompt is raised for a
 * ceremony that could not have been stored.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeyRegistrationOptionsHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal = await personWithPassword(c);
    if (principal instanceof Response) {
      return principal;
    }

    const existing = await listAdminPasskeys(context.db, principal.user.id);
    if (passkeyCapReached(existing.length)) {
      return refuse(
        c,
        "conflict",
        `This account already holds ${String(MAX_PASSKEYS_PER_ACCOUNT)} passkeys, which is the limit. Remove one before adding another.`,
      );
    }

    const party = relyingParty(context.config.publicUrl);
    const options = await generateRegistrationOptions({
      rpName: party.name,
      rpID: party.id,
      userName: principal.user.email,
      userDisplayName: principal.user.displayName,
      // The account identifier, so an authenticator that already holds a
      // credential for this person replaces it rather than accumulating.
      userID: new TextEncoder().encode(principal.user.id),
      attestationType: "none",
      // What stops the same authenticator being registered twice: the browser
      // refuses rather than the server having to detect a duplicate afterwards.
      excludeCredentials: existing.map((passkey) => ({
        id: passkey.credentialId,
        transports: passkey.transports as AuthenticatorTransportFuture[],
      })),
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
    });

    await createAdminPasskeyChallenge(context.db, {
      challenge: options.challenge,
      purpose: "registration",
      adminUserId: principal.user.id,
      expiresAt: challengeExpiry(context),
    });

    return c.json(options);
  };
}

/**
 * Handles `POST /api/v1/account/passkeys`: completes a registration.
 *
 * The challenge is spent inside the library's own verification, through the callback
 * it offers for exactly this: the value being checked is the one from the signed
 * `clientDataJSON`, so there is no second parse of the ceremony to disagree with the
 * first. A challenge that turns out to belong to somebody else is spent all the same
 * and then refused - single use is a property of presenting it, not of presenting it
 * successfully.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeyRegisterHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal = requirePerson(c);
    if (principal instanceof Response) {
      return principal;
    }
    const body = await parseBody(c, passkeyRegistrationSchema);
    if (body instanceof Response) {
      return body;
    }

    const party = relyingParty(context.config.publicUrl);
    let consumed: AdminPasskeyChallenge | undefined;

    const verification = await verifyRegistrationResponse({
      response: body.response as unknown as RegistrationResponseJSON,
      expectedChallenge: async (challenge) => {
        consumed = await consumeAdminPasskeyChallenge(
          context.db,
          challenge,
          "registration",
          context.clock(),
        );
        return consumed?.adminUserId === principal.user.id;
      },
      expectedOrigin: party.origin,
      expectedRPID: party.id,
      requireUserVerification: true,
    }).catch(() => ({ verified: false }) as const);

    if (!verification.verified) {
      return refuse(
        c,
        "invalid_request",
        "That passkey could not be registered. Start again from the passkey list.",
      );
    }

    const credential = verification.registrationInfo.credential;
    const existing = await listAdminPasskeys(context.db, principal.user.id);
    const stored = await insertAdminPasskey(context.db, {
      adminUserId: principal.user.id,
      credentialId: credential.id,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: [...(credential.transports ?? [])],
      name: passkeyName(body.name, existing.length),
    });

    if (!stored.ok) {
      // Both refusals are races against the options request that permitted this
      // one: another ceremony filled the account, or this authenticator was
      // registered in between. Neither is worth distinguishing to the caller.
      return refuse(
        c,
        "invalid_request",
        "That passkey could not be registered. Start again from the passkey list.",
      );
    }

    await recordAuthenticationEvent(
      context,
      requestMetadata(c),
      principal.user,
      "admin.passkey-registered",
      { passkeyId: stored.passkey.id, name: stored.passkey.name },
    );

    return c.json({ passkey: passkeyView(stored.passkey) }, 201);
  };
}

/**
 * Handles `DELETE /api/v1/account/passkeys/:passkeyId`: removes one.
 *
 * The password is confirmed first, and the removal is scoped to the caller's own
 * account in the statement - so another person's identifier is simply not found, and
 * the answer does not disclose that it exists.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeyRemoveHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const principal = await personWithPassword(c);
    if (principal instanceof Response) {
      return principal;
    }

    const passkeyId = c.req.param("passkeyId") ?? "";
    const removed = await removeAdminPasskey(
      context.db,
      principal.user.id,
      passkeyId,
    );
    if (!removed) {
      return refuse(c, "not_found", "No such passkey on this account");
    }

    await recordAuthenticationEvent(
      context,
      requestMetadata(c),
      principal.user,
      "admin.passkey-removed",
      { passkeyId },
    );

    return c.body(null, 204);
  };
}

/**
 * Handles `POST /api/v1/session/passkey-options`: begins a sign-in.
 *
 * `allowCredentials` is left empty deliberately. The browser asks the person which
 * passkey to use, so no identifier is typed and the server is never asked "does this
 * email have a passkey?" - a question whose honest answer enumerates accounts.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeySignInOptionsHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const party = relyingParty(context.config.publicUrl);
    const options = await generateAuthenticationOptions({
      rpID: party.id,
      allowCredentials: [],
      userVerification: "required",
    });

    await createAdminPasskeyChallenge(context.db, {
      challenge: options.challenge,
      purpose: "authentication",
      adminUserId: null,
      expiresAt: challengeExpiry(context),
    });

    return c.json(options);
  };
}

/**
 * Handles `POST /api/v1/session/passkey`: completes a sign-in.
 *
 * The order is: find the credential, spend the challenge and check the signature,
 * then apply the policy. User verification is *not* enforced by the library here -
 * `requireUserVerification` is off and `decidePasskeySignIn` decides instead - so
 * that the rule which lets a passkey stand in for a second factor is stated once, in
 * `@signet/core`, where both its directions are tested.
 *
 * No TOTP is asked for, whatever the account has enrolled. The authenticator
 * verified its user, which is the second factor.
 *
 * @param context - The server's dependencies.
 */
export function adminPasskeySignInHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const metadata = requestMetadata(c);
    const body = await parseBody(c, passkeyAuthenticationSchema);
    if (body instanceof Response) {
      return body;
    }
    const assertion = body as unknown as AuthenticationResponseJSON;

    /** Records the refusal and answers with the one sentence every refusal gets. */
    const refuseSignInAs = async (reason: string, user?: AdminUser) => {
      await recordAuthenticationEvent(
        context,
        metadata,
        user,
        "admin.login-failed",
        { method: "passkey", reason },
      );
      return refuseSignIn(c);
    };

    const registered =
      typeof assertion.id === "string"
        ? await findAdminPasskeyByCredentialId(context.db, assertion.id)
        : undefined;

    if (registered === undefined) {
      // Nothing to verify against, and nobody to attribute the attempt to. The
      // challenge is left to expire rather than being spent by a caller who has
      // not shown they hold anything.
      return await refuseSignInAs("unknown-credential");
    }

    const party = relyingParty(context.config.publicUrl);
    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: async (challenge) =>
        (await consumeAdminPasskeyChallenge(
          context.db,
          challenge,
          "authentication",
          context.clock(),
        )) !== undefined,
      expectedOrigin: party.origin,
      expectedRPID: party.id,
      credential: {
        id: registered.passkey.credentialId,
        publicKey: isoBase64URL.toBuffer(registered.passkey.publicKey),
        counter: registered.passkey.counter,
        transports: registered.passkey
          .transports as AuthenticatorTransportFuture[],
      },
      // Decided by the policy below instead, so the rule has one home.
      requireUserVerification: false,
    }).catch(() => {});

    if (verification === undefined || !verification.verified) {
      return await refuseSignInAs("ceremony-rejected", registered.user);
    }

    const decision = decidePasskeySignIn({
      credential: { counter: registered.passkey.counter },
      accountDisabled: registered.user.disabledAt !== null,
      userVerified: verification.authenticationInfo.userVerified,
      reportedCounter: verification.authenticationInfo.newCounter,
    });
    if (!decision.ok) {
      return await refuseSignInAs(decision.reason, registered.user);
    }

    const recorded = await recordAdminPasskeyUse(
      context.db,
      registered.passkey.id,
      verification.authenticationInfo.newCounter,
      context.clock(),
    );
    if (!recorded) {
      // The statement carries the same counter condition the policy just applied,
      // so this is a concurrent sign-in having advanced it underneath us. Refusing
      // is the conservative reading: one of the two may be a clone.
      return await refuseSignInAs("counter-regressed", registered.user);
    }

    return await establishAdminSession(context, c, registered.user, metadata, {
      method: "passkey",
    });
  };
}
