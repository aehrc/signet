/**
 * The keys a trust anchor or ticket issuer currently publishes.
 *
 * A software statement and a permission ticket are both signed by somebody else,
 * whose keys Signet has to hold an opinion about at the moment the signature is
 * checked. The spec's requirement is that the keys be "fetched fresh or provably
 * current, never assumed", and this module is what makes that true - four
 * properties, each of which is a decision rather than a detail.
 *
 * **Every fetch goes through the outbound guard.** The address comes from an
 * endpoint administrator, not from the operator of the deployment, so it is
 * exactly the untrusted-URL case `../security/outboundFetch.ts` exists for.
 * Adding a second path to the network here would be adding a second SSRF
 * surface.
 *
 * **A cached set is reused for at most {@link REMOTE_JWKS_MAX_AGE_SECONDS}.**
 * That bounds the window in which a key the anchor has withdrawn still verifies,
 * and it is a ceiling rather than a target: past it, the cached document is not
 * consulted at all, even to answer a `kid` it holds.
 *
 * **An unknown `kid` forces one refetch inside that window.** An anchor that
 * rotates its key would otherwise have every statement signed by the new key
 * refused until the cache lapsed. Exactly one refetch: a `kid` that is still
 * absent from the freshly fetched document is remembered as absent, so a
 * statement signed with a key the anchor does not publish costs one outbound
 * request rather than one per attempt. Without that, anybody who can reach the
 * registration endpoint holds an amplifier pointed at the anchor.
 *
 * **A failed fetch refuses.** It never falls back to a stale document and never
 * treats "the anchor is unreachable" as "the anchor vouches for this". An
 * anchor's outage takes registration down, which is the same failure mode as
 * fetching on every request and is the correct one: the alternative is accepting
 * statements against keys nobody can confirm.
 *
 * The cache is a value the caller holds rather than a module-level singleton, in
 * step with the rate-limit store on `ServerContext`: an application is a value,
 * and two applications in one test process must not share the mutable state that
 * decides whether a fetch happens.
 *
 * Author: John Grimes
 */

import { asKeySet } from "../keys/keySet.js";
import { fetchGuardedJson } from "../security/outboundFetch.js";

import type { JSONWebKeySet } from "jose";

/**
 * The longest a fetched key set may be reused, in seconds.
 *
 * Five minutes. Long enough that a burst of registrations costs one fetch,
 * short enough that a withdrawn key stops verifying within a window an operator
 * can state.
 */
export const REMOTE_JWKS_MAX_AGE_SECONDS = 300;

/** Why a key set could not be resolved. */
export type RemoteJwksRefusal =
  /** The address was refused, unreachable, or answered badly. */
  | "fetch-failed"
  /** It answered, with a document that is not a JWK Set. */
  | "not-a-key-set";

/** The outcome of resolving a key set. */
export type RemoteJwksResult =
  | { readonly ok: true; readonly keys: JSONWebKeySet }
  | {
      readonly ok: false;
      readonly reason: RemoteJwksRefusal;
      readonly description: string;
    };

/** One address's most recent successful fetch. */
interface CachedKeySet {
  readonly keys: JSONWebKeySet;
  /** When the document was fetched, as epoch milliseconds. */
  readonly fetchedAt: number;
  /**
   * Key identifiers sought since, and absent from the document as fetched.
   *
   * This is what makes the refetch happen once. A `kid` recorded here has
   * already cost an outbound request during this document's lifetime, so the
   * next attempt with it is answered from the cache and fails verification
   * rather than fetching again.
   */
  readonly missingKids: Set<string>;
}

/**
 * The fetched sets a resolution may reuse, keyed by address.
 *
 * Keyed by the address alone, which is the only key that is safe: a coarser one
 * would let one anchor's statements verify against another anchor's keys.
 */
export type RemoteJwksCache = Map<string, CachedKeySet>;

/**
 * A cache holding nothing.
 *
 * @returns An empty cache, for one application to hold.
 * @example
 * ```ts
 * const context = { ...dependencies, jwksCache: createRemoteJwksCache() };
 * ```
 */
export function createRemoteJwksCache(): RemoteJwksCache {
  return new Map<string, CachedKeySet>();
}

/** What one resolution is about. */
export interface RemoteJwksRequest {
  /** Where the keys are published. Administrator-supplied, hence guarded. */
  readonly jwksUri: string;
  /** The cache to read and write. */
  readonly cache: RemoteJwksCache;
  /** The instant the freshness of a cached document is judged against. */
  readonly now: Date;
  /**
   * The `kid` from the header of the signature about to be verified.
   *
   * Omitted when the caller has no `kid` - a signature without one is verified
   * against whichever published key fits, so there is nothing to refetch for.
   */
  readonly kid?: string;
  /** Permits loopback and private addresses. Development and test stacks only. */
  readonly allowPrivateAddresses?: boolean;
}

/** Whether a set publishes a key under this identifier. */
function publishes(keys: JSONWebKeySet, kid: string): boolean {
  return keys.keys.some((key) => key.kid === kid);
}

/**
 * Whether a cached document may answer this request as it stands.
 *
 * Two reasons it may not, and they are different: the document is past its
 * window, or it does not publish the `kid` and has not already been refetched
 * for it.
 */
function answersFromCache(
  entry: CachedKeySet,
  now: Date,
  kid: string | undefined,
): boolean {
  const age = now.getTime() - entry.fetchedAt;
  if (age >= REMOTE_JWKS_MAX_AGE_SECONDS * 1000) {
    return false;
  }
  if (kid === undefined) {
    return true;
  }
  return publishes(entry.keys, kid) || entry.missingKids.has(kid);
}

/**
 * The keys an address publishes, fetched or reused.
 *
 * @param request - The address, the cache, the instant, and the `kid` being
 *   verified if there is one.
 * @returns The key set, or why it was refused. Never throws for a network or
 *   content failure: each is a value the caller has to audit, and each must
 *   refuse the operation rather than fall back to anything.
 * @example
 * ```ts
 * const resolved = await resolveRemoteJwks({
 *   jwksUri: anchor.jwksUri,
 *   cache: context.jwksCache,
 *   now: context.clock(),
 *   kid: decodeProtectedHeader(statement).kid,
 *   allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
 * });
 * if (!resolved.ok) {
 *   return refuse("invalid_software_statement", resolved.description);
 * }
 * ```
 */
export async function resolveRemoteJwks(
  request: RemoteJwksRequest,
): Promise<RemoteJwksResult> {
  const { cache, jwksUri, kid, now } = request;

  const cached = cache.get(jwksUri);
  if (cached !== undefined && answersFromCache(cached, now, kid)) {
    return { ok: true, keys: cached.keys };
  }

  const fetched = await fetchGuardedJson(jwksUri, {
    allowPrivateAddresses: request.allowPrivateAddresses ?? false,
  });
  if (!fetched.ok) {
    // Deliberately without touching the cache. Poisoning it with the failure
    // would keep the anchor refused for the rest of the window after it came
    // back, and keeping the stale entry costs nothing: it is either past its
    // window, in which case the next attempt fetches again, or it is the entry
    // that could not answer this `kid`, which is still true.
    return {
      ok: false,
      reason: "fetch-failed",
      description: `The published keys at ${jwksUri} could not be fetched: ${fetched.description}`,
    };
  }

  const keys = asKeySet(fetched.value);
  if (keys === undefined) {
    return {
      ok: false,
      reason: "not-a-key-set",
      description: `${jwksUri} did not return a JWK Set`,
    };
  }

  const missingKids = new Set<string>();
  if (kid !== undefined && !publishes(keys, kid)) {
    // Recorded now, against the document just fetched. This is the whole of
    // "refetch once": the next attempt with this `kid` reads the cache and
    // fails verification instead of reaching the anchor again.
    missingKids.add(kid);
  }
  cache.set(jwksUri, { keys, fetchedAt: now.getTime(), missingKids });

  return { ok: true, keys };
}
