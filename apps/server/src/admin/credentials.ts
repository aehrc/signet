/**
 * Minting the credentials the admin API hands out once.
 *
 * Three things are generated here, and all three follow the same rule: the value is
 * returned to the caller exactly once, in the response to the request that created
 * it, and only its digest is stored. There is no "show secret" route, because there
 * is nothing left to show — a lost client secret is rotated, not recovered.
 *
 * Client identifiers are generated too, though they are not secret. A caller may
 * supply one, because a connectathon wants a memorable identifier and a migrating
 * app already has one; when they do not, a name-derived prefix plus random suffix
 * gives an identifier that is recognisable in a log and still unique across the
 * deployment, which `clients.client_id` requires.
 */

import { generateOpaqueToken } from "@signet/db";

/** Random characters appended to a derived client identifier. */
const CLIENT_ID_SUFFIX_LENGTH = 8;

/** Longest prefix derived from the client's name. */
const CLIENT_ID_PREFIX_LENGTH = 32;

/**
 * Derives a URL-safe prefix from a display name.
 *
 * Falls back to `client` when the name yields nothing usable — a name in a script
 * that transliterates to no ASCII at all is perfectly legitimate, and should not
 * produce an identifier beginning with a hyphen.
 *
 * @param name - The client's display name.
 */
export function clientIdPrefix(name: string): string {
  const slug = name
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-")
    .replaceAll(/^-+|-+$/g, "")
    .slice(0, CLIENT_ID_PREFIX_LENGTH)
    .replaceAll(/-+$/g, "");
  return slug.length === 0 ? "client" : slug;
}

/**
 * Generates a client identifier from a display name.
 *
 * The suffix comes from the same generator as every other opaque value, so its
 * entropy is not a separate thing to reason about. It is truncated because a client
 * identifier is typed into app configuration by hand, and this one is not a
 * credential — uniqueness is all it has to provide.
 *
 * @param name - The client's display name.
 */
export function generateClientId(name: string): string {
  const suffix = generateOpaqueToken()
    .replaceAll(/[^a-zA-Z0-9]/g, "")
    .slice(0, CLIENT_ID_SUFFIX_LENGTH)
    .toLowerCase();
  return `${clientIdPrefix(name)}-${suffix}`;
}

/**
 * Generates a client secret.
 *
 * Full length, unlike the identifier: this one is a credential, is copied and
 * pasted rather than typed, and its entropy is the whole point.
 */
export function generateClientSecret(): string {
  return generateOpaqueToken();
}
