/**
 * A stub OpenID Connect provider, on a real socket.
 *
 * The federation suite could have mocked `fetch`, and that would have tested the
 * wrong thing. What has to hold is that Signet, given a provider that behaves like
 * a provider, completes a sign-in - and that means a discovery document at the
 * well-known path, a JWKS containing a key that actually verifies, a token
 * endpoint that reads a form-encoded body, and an ID token signed with the
 * corresponding private key. A mock would have let every one of those be subtly
 * wrong while the suite went green.
 *
 * It listens on loopback through `./localListener.ts`, which is exactly what the
 * outbound-fetch guard is built to refuse - so a suite using this must construct
 * its stack with `allowPrivateOutboundFetches`. That is not an inconvenience to
 * route around: it is the guard proving it works before the test has asserted
 * anything.
 *
 * Every response is controllable, because the interesting tests are the ones where
 * the provider misbehaves: an ID token for another audience, a stale nonce, a
 * userinfo document about a different person.
 *
 * Author: John Grimes
 */

import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { jsonResponse as json, startLocalListener } from "./localListener.js";

import type { JWK, KeyObject } from "jose";

/** How the stub should behave for one test. */
export interface UpstreamIdpOptions {
  /** Claims merged into every ID token, overriding the defaults. */
  readonly idTokenClaims?: Readonly<Record<string, unknown>>;
  /** The userinfo response. Omit for a provider that publishes no userinfo. */
  readonly userinfo?: Readonly<Record<string, unknown>> | undefined;
  /** Fields merged into the discovery document, overriding the defaults. */
  readonly metadata?: Readonly<Record<string, unknown>>;
  /** Answers the token endpoint with this status instead of issuing anything. */
  readonly tokenStatus?: number;
  /**
   * Runs while a request to the provider is being handled, before it is answered.
   *
   * The only moment at which "the outbound request is in flight" is observable from
   * inside the test process: Signet is blocked on this socket, so whatever the
   * database says about Signet's connections now is what it says for the duration of
   * the call.
   */
  readonly whileHandling?: (pathname: string) => Promise<void>;
}

/** A running stub provider. */
export interface UpstreamIdp {
  readonly issuer: string;
  readonly clientId: string;
  /** What the last token request carried, so a test can assert on PKCE. */
  readonly lastTokenRequest: () => Readonly<Record<string, string>> | undefined;
  /** Replaces the behaviour for the next round trip. */
  readonly configure: (options: UpstreamIdpOptions) => void;
  readonly close: () => Promise<void>;
}

/** The default subject the stub signs tokens for. */
export const UPSTREAM_SUBJECT = "upstream-user-1";

/** The client identifier the stub expects Signet to present. */
const UPSTREAM_CLIENT_ID = "signet-test";

/**
 * Starts a stub provider on an ephemeral loopback port.
 *
 * The nonce is echoed from the authorization request rather than fixed, because
 * that is what a real provider does and it is what makes the nonce check
 * meaningful: a test that wants a mismatch overrides the claim explicitly.
 *
 * @param initial - How the provider should behave to begin with.
 */
export async function startUpstreamIdp(
  initial: UpstreamIdpOptions = {},
): Promise<UpstreamIdp> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  jwk.kid = "stub-1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  let options: UpstreamIdpOptions = initial;
  let nonce = "";
  let lastTokenRequest: Record<string, string> | undefined;

  const server = await startLocalListener(async (request, issuer) => {
    const url = new URL(request.url);
    await options.whileHandling?.(url.pathname);

    if (url.pathname === "/.well-known/openid-configuration") {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        ...(options.userinfo === undefined
          ? {}
          : { userinfo_endpoint: `${issuer}/userinfo` }),
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["RS256"],
        ...options.metadata,
      });
    }

    if (url.pathname === "/jwks") {
      return json({ keys: [jwk] });
    }

    if (url.pathname === "/authorize") {
      // Remembered so the ID token can echo it, exactly as a provider would.
      nonce = url.searchParams.get("nonce") ?? "";
      return json({ ok: true });
    }

    if (url.pathname === "/token") {
      lastTokenRequest = Object.fromEntries(
        new URLSearchParams(await request.text()),
      );
      if (options.tokenStatus !== undefined) {
        return json({ error: "invalid_grant" }, options.tokenStatus);
      }
      return json({
        access_token: "upstream-access-token",
        token_type: "Bearer",
        id_token: await signIdToken(privateKey, issuer, nonce, options),
      });
    }

    if (url.pathname === "/userinfo") {
      return options.userinfo === undefined
        ? json({ error: "not_found" }, 404)
        : json({ sub: UPSTREAM_SUBJECT, ...options.userinfo });
    }

    return json({ error: "not_found" }, 404);
  });

  return {
    issuer: server.origin,
    clientId: UPSTREAM_CLIENT_ID,
    lastTokenRequest: () => lastTokenRequest,
    configure: (next) => {
      options = next;
    },
    close: server.close,
  };
}

/** Signs an ID token the way the provider under test would. */
async function signIdToken(
  privateKey: KeyObject | CryptoKey,
  issuer: string,
  nonce: string,
  options: UpstreamIdpOptions,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    sub: UPSTREAM_SUBJECT,
    aud: UPSTREAM_CLIENT_ID,
    nonce,
    iat: now,
    exp: now + 300,
    ...options.idTokenClaims,
  };
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "stub-1" })
    .setIssuer(typeof claims["iss"] === "string" ? claims["iss"] : issuer)
    .sign(privateKey);
}

/** A JWK, for a test that needs to look at the stub's key. */
export type UpstreamJwk = JWK;
