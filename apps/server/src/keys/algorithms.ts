/**
 * The signing algorithms an endpoint may use.
 *
 * SMART App Launch requires RS384 or ES384 for a client's `private_key_jwt`
 * assertion, and Signet signs its own tokens with the same pair rather than
 * introducing a third: a resource server that can verify a client assertion can
 * then verify a Signet token with no further configuration.
 *
 * Kept in its own module because both the key material and the discovery document
 * need the list, and importing the material module — which pulls in `jose` and
 * the envelope cipher — merely to name two strings would be a needless
 * dependency in the discovery path.
 */

/** An algorithm an endpoint signing key may use. */
export type EndpointKeyAlgorithm = "RS384" | "ES384";

/**
 * Every permitted algorithm, in the order `id_token_signing_alg_values_supported`
 * advertises them.
 *
 * RS384 first because it is the more widely implemented of the two, and a client
 * library that takes the first entry it recognises should land on the one most
 * likely to work.
 */
export const ENDPOINT_KEY_ALGORITHMS: readonly EndpointKeyAlgorithm[] = [
  "RS384",
  "ES384",
];

/** Narrows a stored column value to the algorithm union. */
export function isEndpointKeyAlgorithm(
  value: string,
): value is EndpointKeyAlgorithm {
  return (ENDPOINT_KEY_ALGORITHMS as readonly string[]).includes(value);
}
