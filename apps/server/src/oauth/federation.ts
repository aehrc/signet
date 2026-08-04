/**
 * Brokering an authorization to an upstream identity provider.
 *
 * Signet is the authorization server an app talks to; for an endpoint in `oidc`
 * auth mode it is also a relying party of somebody else's. Two handlers make up
 * the round trip: `/federation/start` sends the browser to the provider, and
 * `/federation/callback` receives it back, verifies what it brought, and resumes
 * the authorization that was already in flight.
 *
 * Four things protect the round trip, and none of them is optional.
 *
 * **State.** A single-use, endpoint-scoped row, looked up by digest. It proves the
 * callback belongs to a request Signet made, and consuming it in a conditional
 * update means a replayed callback finds nothing rather than signing somebody in
 * twice.
 *
 * **Nonce.** Minted with the state and checked against the ID token. This is what
 * ties the token to *this* sign-in - without it an ID token captured from an
 * earlier session can be injected into a later one.
 *
 * **PKCE.** Sent to the provider whether it advertises support or not. A provider
 * that ignores it is no worse off than one that was never sent a challenge, and a
 * provider that honours it makes a stolen code useless.
 *
 * **The SSRF guard.** Every outbound request - discovery, JWKS, token, userinfo -
 * goes through it, because all four URLs are ultimately derived from a discovery
 * document at an operator-supplied address.
 *
 * What the handlers never do is tell the browser why a sign-in failed in terms of
 * the upstream provider. A callback that cannot be verified is one refusal with
 * one message; the reason goes to the audit trail, where an operator can read it
 * and an attacker cannot.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
 *
 * Author: John Grimes
 */

import {
  federatedUsername,
  mapUpstreamClaims,
  mergeClaims,
  supportsPkce,
  validateUpstreamIdToken,
  validateUpstreamMetadata,
} from "@signet/core";
import {
  consumeFederationState,
  createFederationState,
  decryptSecret,
  generateOpaqueToken,
  getIdpConfig,
  getLiveAuthorizationSession,
  hashToken,
  recordIdpDiscoveryFetch,
  upsertFederatedEndUser,
  withTenantScope,
} from "@signet/db";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";

import { recordEndUserEvent } from "./endUserAudit.js";
import { resumeAuthenticatedSession } from "./interaction.js";
import { requestMetadata } from "../http/requestMeta.js";
import { asKeySet } from "../keys/keySet.js";
import { logRecord } from "../observability/log.js";
import { fetchGuardedJson } from "../security/outboundFetch.js";

import type {
  ResolvedIssuerContext,
  ServerContext,
  SignetEnvironment,
} from "../context.js";
import type { UpstreamMetadata } from "@signet/core";
import type { AuthorizationSession, IdpConfig } from "@signet/db";
import type { Context } from "hono";

/**
 * How long a federation round trip may take, in seconds.
 *
 * Ten minutes: long enough for somebody to find their authenticator app, short
 * enough that an abandoned sign-in is not still redeemable an hour later.
 */
export const FEDERATION_STATE_TTL_SECONDS = 600;

/**
 * The scopes requested upstream when an operator configured none.
 *
 * `openid` is mandatory for the flow to produce an ID token at all; `profile` is
 * what makes a display name available. Nothing else is assumed - an operator who
 * needs group membership names the scope that carries it, because guessing is how
 * a relying party ends up asking for more than it needs.
 */
const DEFAULT_UPSTREAM_SCOPES: readonly string[] = ["openid", "profile"];

/** Where the provider sends the browser back to. */
export function federationCallbackUrl(issuer: string): string {
  return `${issuer}/federation/callback`;
}

/** Everything loaded before a round trip can start or finish. */
interface FederationSetup {
  readonly config: IdpConfig;
  readonly metadata: UpstreamMetadata;
}

/**
 * The refusal every federation failure produces.
 *
 * One message and one status for all of them. The distinctions that matter -
 * unknown state, replayed callback, bad nonce, provider unreachable - are in the
 * audit trail; putting them in the response would build an oracle for whoever is
 * probing the callback.
 */
function refuseSignIn(c: Context<SignetEnvironment>) {
  return c.json(
    {
      error: "access_denied",
      error_description: "The sign-in could not be completed",
    },
    400,
  );
}

/**
 * Records a federation event.
 *
 * A thin shape over the shared recorder: every event here is about a person and
 * is marked with the surface, because a sign-in failure at an identity provider
 * and one at a password form are different problems with different fixes, and an
 * operator reading the trail needs to see which they are looking at.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the sign-in belongs to.
 * @param metadata - Request metadata for the trail.
 * @param event - The action, what to say about it, and who it was, if known.
 * @param event.action - Whether the sign-in succeeded.
 * @param event.detail - What to record about it.
 * @param event.endUserId - The account, once one is known.
 * @param event.displayName - The account's name, once one is known.
 */
async function recordFederationEvent(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
  event: {
    readonly action: "end-user.login" | "end-user.login-failed";
    readonly detail: Record<string, unknown>;
    readonly endUserId?: string;
    readonly displayName?: string;
  },
): Promise<void> {
  await recordEndUserEvent(context, issuerContext, metadata, {
    ...event,
    target: { type: "end-user" },
    detail: { surface: "federation", ...event.detail },
  });
}

/**
 * Loads the provider configuration and its discovery document.
 *
 * Fetched on every round trip rather than cached. A cached document that outlived
 * a provider's key rotation or endpoint move would fail in a way nobody could
 * explain, and this happens twice per sign-in rather than once per request - the
 * same trade `loadClientKeySet` makes, for the same reason.
 */
async function loadSetup(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
): Promise<
  | { readonly ok: true; readonly setup: FederationSetup }
  | { readonly ok: false; readonly reason: string }
> {
  const config = await withTenantScope(
    context.db,
    issuerContext.scope,
    (bound) => getIdpConfig(bound),
  );
  if (config === undefined) {
    return { ok: false, reason: "no-idp-configured" };
  }

  const allowPrivate = context.config.allowPrivateOutboundFetches;
  const discoveryUrl = `${config.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const fetched = await fetchGuardedJson(discoveryUrl, {
    allowPrivateAddresses: allowPrivate,
  });
  if (!fetched.ok) {
    return { ok: false, reason: `discovery-${fetched.reason}` };
  }
  await withTenantScope(context.db, issuerContext.scope, (bound) =>
    recordIdpDiscoveryFetch(bound, context.clock()),
  );

  const validated = validateUpstreamMetadata(fetched.value, config.issuer, {
    // The same flag that relaxes the address guard relaxes the scheme rule, and
    // for the same deployment: a provider on a compose network is `http://`.
    allowInsecureEndpoints: allowPrivate,
  });
  if (!validated.ok) {
    return { ok: false, reason: `discovery-${validated.code}` };
  }

  return { ok: true, setup: { config, metadata: validated.metadata } };
}

/**
 * Sends the browser to the provider.
 *
 * The session is loaded first, and a session that is already signed into is left
 * alone: a reloaded start URL must not mint a second round trip against an
 * authorization that has moved on.
 *
 * @param context - The server's dependencies.
 */
export function federationStartHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);

    if (issuerContext.endpoint.authMode !== "oidc") {
      return c.json(
        {
          error: "invalid_request",
          error_description: "This endpoint does not federate authentication",
        },
        400,
      );
    }

    const session = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) =>
        getLiveAuthorizationSession(bound, c.req.query("session") ?? ""),
    );
    if (session === undefined || session.endUserId !== null) {
      return refuseSignIn(c);
    }

    const loaded = await loadSetup(context, issuerContext);
    if (!loaded.ok) {
      await recordFederationEvent(context, issuerContext, metadata, {
        action: "end-user.login-failed",
        detail: { reason: loaded.reason, phase: "start" },
      });
      return refuseSignIn(c);
    }

    return c.redirect(
      await startRoundTrip(context, issuerContext, loaded.setup, session),
      302,
    );
  };
}

/**
 * Mints the state, nonce and PKCE pair and builds the upstream URL.
 *
 * The state is the only one of the three the browser ever sees, and it is stored
 * as a digest - so the row cannot be found by anybody who has only read the
 * database, and the value in the URL is not a credential that unlocks it.
 */
async function startRoundTrip(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  setup: FederationSetup,
  session: AuthorizationSession,
): Promise<string> {
  const state = generateOpaqueToken();
  const nonce = generateOpaqueToken();
  const codeVerifier = generateOpaqueToken();

  const stateHash = await hashToken(state);
  await withTenantScope(context.db, issuerContext.scope, (bound) =>
    createFederationState(bound, session, {
      stateHash,
      nonce,
      codeVerifier,
      expiresAt: new Date(
        context.clock().getTime() + FEDERATION_STATE_TTL_SECONDS * 1000,
      ),
    }),
  );

  const url = new URL(setup.metadata.authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", setup.config.clientId);
  url.searchParams.set(
    "redirect_uri",
    federationCallbackUrl(issuerContext.issuer),
  );
  url.searchParams.set(
    "scope",
    (setup.config.scopes.length > 0
      ? setup.config.scopes
      : DEFAULT_UPSTREAM_SCOPES
    ).join(" "),
  );
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  // Always sent. A provider that does not understand PKCE ignores these, which
  // leaves us exactly where we would have been without them; one that does makes
  // an intercepted code unusable.
  url.searchParams.set("code_challenge", await pkceChallenge(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  if (!supportsPkce(setup.metadata)) {
    // Worth a line in the log: an operator who believes PKCE is protecting this
    // flow should be told when the provider says it is not.
    logRecord(
      context.config.logLevel,
      "warn",
      "signet.federation.pkce-unsupported",
      { issuer: setup.config.issuer },
    );
  }
  return url.toString();
}

/** S256 challenge for a verifier, per RFC 7636 §4.2. */
async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return Buffer.from(digest)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

/**
 * Receives the browser back from the provider.
 *
 * @param context - The server's dependencies.
 */
export function federationCallbackHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);

    if (issuerContext.endpoint.authMode !== "oidc") {
      return refuseSignIn(c);
    }

    /** Audits the failure and answers with the one uniform refusal. */
    const fail = async (
      reason: string,
      detail: Record<string, unknown> = {},
    ) => {
      await recordFederationEvent(context, issuerContext, metadata, {
        action: "end-user.login-failed",
        detail: { reason, phase: "callback", ...detail },
      });
      return refuseSignIn(c);
    };

    // An `error` from the provider is the person declining, or the provider
    // refusing. Either way it is not our failure to diagnose - it is recorded and
    // the sign-in ends.
    const upstreamError = c.req.query("error");
    if (upstreamError !== undefined) {
      return await fail("upstream-error", { upstreamError });
    }

    const state = c.req.query("state");
    const code = c.req.query("code");
    if (state === undefined || code === undefined) {
      return await fail("missing-parameters");
    }

    const stateHash = await hashToken(state);
    const claimed = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => consumeFederationState(bound, stateHash, context.clock()),
    );
    if (claimed === undefined) {
      // Unknown, expired, already used, or another endpoint's - all one refusal.
      return await fail("state-not-claimable");
    }

    const loaded = await loadSetup(context, issuerContext);
    if (!loaded.ok) {
      return await fail(loaded.reason);
    }

    const identity = await resolveIdentity(context, loaded.setup, {
      code,
      codeVerifier: claimed.state.codeVerifier,
      nonce: claimed.state.nonce,
      redirectUri: federationCallbackUrl(issuerContext.issuer),
    });
    if (!identity.ok) {
      return await fail(identity.reason);
    }

    const mapped = mapUpstreamClaims(
      loaded.setup.config.claimMappings,
      identity.claims,
    );
    const user = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) =>
        upsertFederatedEndUser(bound, {
          username: federatedUsername(
            loaded.setup.metadata.issuer,
            identity.subject,
          ),
          // The provider is not obliged to send a name, and an account with a blank
          // one is unreadable in the console - so the subject stands in for it.
          displayName: mapped.displayName ?? identity.subject,
          fhirUserReference: mapped.fhirUser ?? null,
          roles: mapped.roles,
          attributes: mapped.attributes,
        }),
    );

    await recordFederationEvent(context, issuerContext, metadata, {
      action: "end-user.login",
      endUserId: user.id,
      displayName: user.displayName,
      detail: {
        issuer: loaded.setup.metadata.issuer,
        fhirUser: user.fhirUserReference,
        roles: user.roles,
      },
    });

    const destination = await resumeAuthenticatedSession(
      context,
      issuerContext,
      claimed.session.id,
      user,
      metadata,
    );
    if (destination === undefined) {
      return await fail("session-gone");
    }
    return c.redirect(destination, 302);
  };
}

/** What the code exchange and verification produced. */
type IdentityResolution =
  | {
      readonly ok: true;
      readonly subject: string;
      readonly claims: Readonly<Record<string, unknown>>;
    }
  | { readonly ok: false; readonly reason: string };

/**
 * Redeems the code and verifies the ID token it came with.
 *
 * The order is deliberate: signature first, then claims, then userinfo. Verifying
 * claims on a token whose signature has not been checked would be reasoning about
 * a document anybody could have written, and fetching userinfo before either
 * would send the access token somewhere on the strength of a document we had not
 * yet decided to trust.
 */
async function resolveIdentity(
  context: ServerContext,
  setup: FederationSetup,
  exchange: {
    readonly code: string;
    readonly codeVerifier: string;
    readonly nonce: string;
    readonly redirectUri: string;
  },
): Promise<IdentityResolution> {
  const allowPrivate = context.config.allowPrivateOutboundFetches;

  const secret = await upstreamSecret(context, setup.config);
  if (!secret.ok) {
    return { ok: false, reason: "client-secret-undecryptable" };
  }

  const redeemed = await fetchGuardedJson<Record<string, unknown>>(
    setup.metadata.tokenEndpoint,
    {
      allowPrivateAddresses: allowPrivate,
      form: {
        grant_type: "authorization_code",
        code: exchange.code,
        redirect_uri: exchange.redirectUri,
        client_id: setup.config.clientId,
        code_verifier: exchange.codeVerifier,
        // Sent in the body rather than as Basic auth. Both are permitted; a
        // provider that wants Basic accepts this too, and one credential
        // transport is one place to get the encoding wrong.
        ...(secret.value === undefined ? {} : { client_secret: secret.value }),
      },
    },
  );
  if (!redeemed.ok) {
    return { ok: false, reason: `token-${redeemed.reason}` };
  }

  const idToken = redeemed.value["id_token"];
  if (typeof idToken !== "string") {
    return { ok: false, reason: "no-id-token" };
  }

  const keys = await fetchGuardedJson(setup.metadata.jwksUri, {
    allowPrivateAddresses: allowPrivate,
  });
  if (!keys.ok) {
    return { ok: false, reason: `jwks-${keys.reason}` };
  }
  const keySet = asKeySet(keys.value);
  if (keySet === undefined) {
    return { ok: false, reason: "jwks-not-a-key-set" };
  }

  try {
    await jwtVerify(idToken, createLocalJWKSet(keySet));
  } catch {
    return { ok: false, reason: "id-token-signature" };
  }

  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(idToken);
  } catch {
    return { ok: false, reason: "id-token-malformed" };
  }

  const validated = validateUpstreamIdToken({
    claims,
    expectedIssuer: setup.metadata.issuer,
    clientId: setup.config.clientId,
    expectedNonce: exchange.nonce,
    nowSeconds: Math.floor(context.clock().getTime() / 1000),
  });
  if (!validated.ok) {
    return { ok: false, reason: `id-token-${validated.code}` };
  }

  const userinfo = await fetchUserinfo(
    context,
    setup,
    redeemed.value["access_token"],
    validated.token.subject,
  );
  if (!userinfo.ok) {
    return { ok: false, reason: userinfo.reason };
  }

  return {
    ok: true,
    subject: validated.token.subject,
    claims: mergeClaims(claims, userinfo.claims),
  };
}

/** The userinfo response, or the reason the sign-in must stop. */
type UserinfoResult =
  | {
      readonly ok: true;
      readonly claims: Readonly<Record<string, unknown>> | undefined;
    }
  | { readonly ok: false; readonly reason: string };

/**
 * Fetches userinfo, when there is one to fetch and a token to fetch it with.
 *
 * A provider with no userinfo endpoint is not an error: the ID token's claims are
 * a complete answer, and plenty of providers put everything there. A *mismatched*
 * `sub` is an error, and a fatal one - Core §5.3.2 requires the response to be
 * rejected, because a userinfo document about a different person is either a
 * misconfigured provider or an attempt to graft one identity onto another's
 * sign-in.
 *
 * A userinfo request that simply fails is also fatal rather than skipped. The
 * mapping may take `fhirUser` from it, and continuing without it would provision
 * an account with less authority than the person actually has - which reads as a
 * permissions bug rather than as the network failure it is.
 */
async function fetchUserinfo(
  context: ServerContext,
  setup: FederationSetup,
  accessToken: unknown,
  subject: string,
): Promise<UserinfoResult> {
  const endpoint = setup.metadata.userinfoEndpoint;
  if (endpoint === undefined || typeof accessToken !== "string") {
    return { ok: true, claims: undefined };
  }

  const fetched = await fetchGuardedJson<Record<string, unknown>>(endpoint, {
    allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!fetched.ok) {
    return { ok: false, reason: `userinfo-${fetched.reason}` };
  }
  if (fetched.value["sub"] !== subject) {
    return { ok: false, reason: "userinfo-subject-mismatch" };
  }
  return { ok: true, claims: fetched.value };
}

/** The upstream client secret, decrypted, or undefined for a public client. */
async function upstreamSecret(
  context: ServerContext,
  config: IdpConfig,
): Promise<
  | { readonly ok: true; readonly value: string | undefined }
  | { readonly ok: false }
> {
  if (config.clientSecretEncrypted === null) {
    return { ok: true, value: undefined };
  }
  try {
    return {
      ok: true,
      value: await decryptSecret(
        config.clientSecretEncrypted,
        context.config.masterKey,
      ),
    };
  } catch {
    // A secret that will not decrypt means the master key has changed. Reported
    // as its own reason, because the fix is an operator re-entering the secret
    // rather than anything to do with the provider.
    return { ok: false };
  }
}
