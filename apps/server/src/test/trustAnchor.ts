/**
 * A stand-in trust anchor and ticket issuer, on a real socket.
 *
 * The connectathon programme's anchor is Muster, and Signet's suites must not
 * depend on it existing. So this helper is the counterparty: it generates ES256
 * keys in the test process, publishes their public halves as a JWK Set on a
 * loopback listener, and mints the software statements and permission tickets
 * that the registration endpoint and the exchange grant are asked to verify.
 *
 * Everything a suite has to be able to arrange is arrangeable here, because the
 * interesting assertions are refusals and a refusal is only evidence if the
 * fixture failed for the reason the test names:
 *
 * - **Expiry** is a lifetime, so an expired statement is one whose signature is
 *   still perfectly good.
 * - **A tampered signature** is {@link tamperJws}, which leaves the claims
 *   decodable so "the signature did not verify" cannot be confused with "the JWT
 *   was malformed".
 * - **Rotation** is {@link TrustAnchor.addKey}, which publishes a second key and
 *   leaves the first in the set - the case where a statement signed by a
 *   superseded key must still verify. {@link TrustAnchor.withdrawKey} is the
 *   other half: a key absent from the published set must not.
 * - **An unknown `kid`** is a key added with `publish: false`, which is what
 *   forces the JWKS cache to refetch.
 * - **An unreachable anchor** is {@link TrustAnchor.failJwksWith}, since the
 *   rule is that a fetch failure refuses rather than falling back.
 *
 * {@link TrustAnchor.jwksFetches} counts what the anchor served, which is how a
 * cache is shown to be caching. There is no other way to observe it: the cache
 * is in-process and a hit is the absence of a request.
 *
 * The listener binds loopback by default, so a suite fetching from it must build
 * its stack with `allowPrivateOutboundFetches`. The end-to-end suite runs Signet
 * in a container, where the host's loopback is not reachable, so it binds every
 * address and advertises `host.docker.internal` instead - see
 * `e2e/support/trustAnchor.ts` and `./localListener.ts`.
 *
 * The claim defaults below are the shapes the registration profile and the
 * ticket profile use; every one of them is overridable per mint, so a suite that
 * needs a different shape states it rather than editing this file.
 *
 * Author: John Grimes
 */

import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { jsonResponse, startLocalListener } from "./localListener.js";

import type { LocalListenerOptions } from "./localListener.js";
import type { JWK, KeyObject } from "jose";

/** The algorithm every key here is generated and every token signed with. */
export const TRUST_ANCHOR_ALGORITHM = "ES256";

/** The ticket type the connectathon programme exercises. */
export const DEFAULT_TICKET_TYPE = "patient-self-access";

/** The identifier system the programme's ticket subjects are expressed in. */
export const DEFAULT_SUBJECT_SYSTEM =
  "http://ns.electronichealth.net.au/id/hi/ihi/1.0";

/** An IHI belonging to the patient the stack's seed data creates. */
export const DEFAULT_SUBJECT_VALUE = "8003608500314687";

/** How one minted statement or ticket should differ from the default. */
export interface MintOptions {
  /**
   * Claims merged over the defaults, and over `iss`, `iat`, `exp` and `jti`.
   *
   * Merged last deliberately: a suite that needs a fixed `jti` to assert replay,
   * or a missing claim to assert a refusal, sets it here and nothing overrides
   * it back.
   */
  readonly claims?: Readonly<Record<string, unknown>>;
  /** Which of the anchor's keys signs. Defaults to the current one. */
  readonly kid?: string;
  /** Overrides `iss`, for the wrong-issuer refusal. */
  readonly issuer?: string;
  /** Seconds from `issuedAt` to `exp`. Negative mints an expired token. */
  readonly lifetimeSeconds?: number;
  /** The instant `iat` records, defaulting to now. */
  readonly issuedAt?: Date;
}

/** A running anchor, with everything a suite needs to drive it. */
export interface TrustAnchor {
  /** The anchor's issuer identifier, which its tokens claim as `iss`. */
  readonly issuer: string;
  /** Where its public keys are published. Private, so guarded fetches refuse it. */
  readonly jwksUri: string;
  /** The `kid` new tokens are signed with. Changes with {@link addKey}. */
  readonly keyId: string;
  /** How many times the JWK Set has been served since the anchor started. */
  readonly jwksFetches: () => number;
  /** Mints a software statement, per the registration profile. */
  readonly mintStatement: (options?: MintOptions) => Promise<string>;
  /** Mints a permission ticket, per the ticket profile. */
  readonly mintTicket: (options?: MintOptions) => Promise<string>;
  /**
   * Generates another key and makes it the signing key.
   *
   * @returns The new key's `kid`.
   */
  readonly addKey: (options?: {
    readonly publish?: boolean;
  }) => Promise<string>;
  /** Removes a key from the published set, without discarding its private half. */
  readonly withdrawKey: (kid: string) => void;
  /** Answers the JWKS with this status instead of the document. */
  readonly failJwksWith: (status: number | undefined) => void;
  readonly close: () => Promise<void>;
}

/** How the anchor should be configured. */
export interface TrustAnchorOptions {
  /**
   * The issuer identifier its tokens claim.
   *
   * Defaults to the listener's own origin, which is what a real anchor publishing
   * its keys under its issuer would use.
   */
  readonly issuer?: string;
  /**
   * Where the listener binds, and what it calls itself.
   *
   * Loopback by default, which is what an in-process suite wants. The end-to-end
   * suite is the exception: Signet runs in a container there, so the anchor binds
   * every address and advertises a name the container resolves.
   */
  readonly listener?: LocalListenerOptions;
}

/** One of the anchor's keys, published or not. */
interface AnchorKey {
  readonly kid: string;
  readonly privateKey: KeyObject | CryptoKey;
  readonly publicJwk: JWK;
  published: boolean;
}

/** The claims a software statement carries when nothing overrides them. */
function defaultStatementClaims(): Record<string, unknown> {
  return {
    client_name: "Vouched test app",
    redirect_uris: ["https://app.example.org/callback"],
    grant_types: ["authorization_code", "refresh_token"],
    token_endpoint_auth_method: "none",
    scope: "launch/patient openid fhirUser patient/*.rs",
  };
}

/** The claims a permission ticket carries when nothing overrides them. */
function defaultTicketClaims(): Record<string, unknown> {
  return {
    ticket_type: DEFAULT_TICKET_TYPE,
    subject: { system: DEFAULT_SUBJECT_SYSTEM, value: DEFAULT_SUBJECT_VALUE },
    smart_scopes: ["patient/Patient.rs"],
  };
}

/**
 * Starts an anchor on an ephemeral loopback port.
 *
 * @param options - How the anchor should be configured.
 * @returns The running anchor. Close it, or the socket outlives the suite.
 * @example
 * ```ts
 * const anchor = await startTrustAnchor();
 * const statement = await anchor.mintStatement({ lifetimeSeconds: -60 });
 * await anchor.close();
 * ```
 */
export async function startTrustAnchor(
  options: TrustAnchorOptions = {},
): Promise<TrustAnchor> {
  const keys: AnchorKey[] = [await generateAnchorKey(0)];
  let current = keys[0]?.kid ?? "";
  let fetches = 0;
  let failureStatus: number | undefined;

  const listener = await startLocalListener(async (request) => {
    const url = new URL(request.url);
    if (url.pathname !== "/jwks") {
      return await Promise.resolve(jsonResponse({ error: "not_found" }, 404));
    }

    // Counted before the failure is applied: a suite asserting "the fetch was
    // attempted and refused" needs the attempt to show up.
    fetches += 1;
    return await Promise.resolve(
      failureStatus === undefined
        ? jsonResponse({
            keys: keys
              .filter((key) => key.published)
              .map((key) => key.publicJwk),
          })
        : jsonResponse({ error: "unavailable" }, failureStatus),
    );
  }, options.listener ?? {});

  const issuer = options.issuer ?? listener.origin;

  /** Signs a token with the anchor's keys and the caller's overrides. */
  const mint = async (
    defaults: Record<string, unknown>,
    mintOptions: MintOptions,
  ): Promise<string> => {
    const kid = mintOptions.kid ?? current;
    const key = keys.find((candidate) => candidate.kid === kid);
    if (key === undefined) {
      throw new Error(`the anchor holds no key with kid ${kid}`);
    }

    const issuedAt = mintOptions.issuedAt ?? new Date();
    const issuedAtSeconds = Math.floor(issuedAt.getTime() / 1000);
    const claims: Record<string, unknown> = {
      ...defaults,
      iss: mintOptions.issuer ?? issuer,
      iat: issuedAtSeconds,
      exp: issuedAtSeconds + (mintOptions.lifetimeSeconds ?? 300),
      jti: crypto.randomUUID(),
      ...mintOptions.claims,
    };

    return await new SignJWT(claims)
      .setProtectedHeader({ alg: TRUST_ANCHOR_ALGORITHM, kid })
      .sign(key.privateKey);
  };

  return {
    issuer,
    jwksUri: `${listener.origin}/jwks`,
    get keyId() {
      return current;
    },
    jwksFetches: () => fetches,
    mintStatement: async (mintOptions = {}) =>
      await mint(defaultStatementClaims(), mintOptions),
    mintTicket: async (mintOptions = {}) =>
      await mint(defaultTicketClaims(), mintOptions),
    addKey: async ({ publish = true } = {}) => {
      const key = await generateAnchorKey(keys.length);
      key.published = publish;
      keys.push(key);
      current = key.kid;
      return key.kid;
    },
    withdrawKey: (kid) => {
      const key = keys.find((candidate) => candidate.kid === kid);
      if (key === undefined) {
        throw new Error(`the anchor holds no key with kid ${kid}`);
      }
      key.published = false;
    },
    failJwksWith: (status) => {
      failureStatus = status;
    },
    close: listener.close,
  };
}

/** Generates one key pair and the JWK the anchor publishes for it. */
async function generateAnchorKey(index: number): Promise<AnchorKey> {
  const { publicKey, privateKey } = await generateKeyPair(
    TRUST_ANCHOR_ALGORITHM,
    { extractable: true },
  );
  const publicJwk = await exportJWK(publicKey);
  // Unique per anchor as well as per key, so two anchors in one suite cannot
  // produce a statement that verifies against the other's document by accident.
  publicJwk.kid = `anchor-${crypto.randomUUID().slice(0, 8)}-${String(index)}`;
  publicJwk.alg = TRUST_ANCHOR_ALGORITHM;
  publicJwk.use = "sig";

  return {
    kid: publicJwk.kid,
    privateKey,
    publicJwk,
    published: true,
  };
}

/**
 * Corrupts a JWS's signature, leaving its header and claims intact.
 *
 * The signature is edited rather than the payload rewritten, so the token still
 * parses and still decodes: a suite asserting a signature refusal is then
 * asserting that, and not that the JWT was malformed.
 *
 * The *first* character, not the last. An ES256 signature is 64 bytes in 86
 * base64url characters, and 86 characters encode 516 bits - so the final
 * character carries four bits that decode to nothing, and changing it can leave
 * the signature bytes identical. That produced a test which passed most of the
 * time, which is worse than one that never did.
 *
 * @param jws - A compact JWS.
 * @returns The same token with a signature that cannot verify.
 * @throws {Error} When the input is not a three-part compact JWS.
 * @example
 * ```ts
 * const refused = tamperJws(await anchor.mintStatement());
 * ```
 */
export function tamperJws(jws: string): string {
  const parts = jws.split(".");
  const signature = parts[2];
  if (parts.length !== 3 || signature === undefined || signature.length === 0) {
    throw new Error("tamperJws expects a compact JWS with three parts");
  }

  const replacement = signature.startsWith("A") ? "B" : "A";
  parts[2] = replacement + signature.slice(1);
  return parts.join(".");
}
