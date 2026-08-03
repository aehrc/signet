/**
 * Narrowing an arbitrary JSON document to a JWK Set.
 *
 * Two places fetch keys from somebody else's server - a client's `jwks_uri` and an
 * upstream identity provider's - and both then hand the result to `jose`. Checking
 * the shape here rather than at each of them means a malformed document produces a
 * specific message instead of an exception from inside the library, and it means
 * the check cannot be present at one call site and forgotten at the other.
 *
 * Only the `keys` array is checked, because that is all `createLocalJWKSet`
 * requires: it validates each key itself and ignores anything it cannot use.
 */

import type { JSONWebKeySet } from "jose";

/**
 * Reads a fetched document as a JWK Set.
 *
 * @param document - The parsed JSON, as fetched. Untrusted.
 * @returns The key set, or undefined when the document has no `keys` array.
 */
export function asKeySet(document: unknown): JSONWebKeySet | undefined {
  return typeof document === "object" &&
    document !== null &&
    Array.isArray((document as { keys?: unknown }).keys)
    ? (document as JSONWebKeySet)
    : undefined;
}
