/**
 * The signing algorithms an endpoint may use.
 *
 * SMART App Launch requires RS384 or ES384 for a client's `private_key_jwt`
 * assertion, and Signet defaults to the same pair for its own tokens: a resource
 * server that can verify a client assertion can then verify a Signet token with
 * no further configuration.
 *
 * **RS256 is here for a reason worth writing down.** Spring Security's JWT
 * decoder accepts RS256 and nothing else unless an application configures
 * otherwise, and several FHIR servers - Pathling among them - build their
 * decoder from an issuer URL without configuring it. Such a server rejects an
 * RS384 token with "another algorithm expected", which is a message that sends an
 * operator looking at their keys rather than at the default they cannot see.
 * Signet can therefore be configured to meet them, deliberately and per endpoint.
 *
 * RS256 is not the default and should not be chosen without that reason. It is a
 * weaker digest than SMART asks for anywhere else in the protocol, and an
 * endpoint using it advertises the fact in its discovery document, where an app
 * can see it.
 *
 * Kept in its own module because both the key material and the discovery document
 * need the list, and importing the material module - which pulls in `jose` and
 * the envelope cipher - merely to name three strings would be a needless
 * dependency in the discovery path.
 *
 * Author: John Grimes
 */

/** An algorithm an endpoint signing key may use. */
export type EndpointKeyAlgorithm = "RS384" | "ES384" | "RS256";

/**
 * Every permitted algorithm, in the order `id_token_signing_alg_values_supported`
 * advertises them.
 *
 * RS384 first because it is what SMART asks for and the more widely implemented
 * of the two it names, so a client library that takes the first entry it
 * recognises lands on the one most likely to work. RS256 last, because it is the
 * compatibility choice rather than the recommended one.
 */
export const ENDPOINT_KEY_ALGORITHMS: readonly EndpointKeyAlgorithm[] = [
  "RS384",
  "ES384",
  "RS256",
];

/** Narrows a stored column value to the algorithm union. */
export function isEndpointKeyAlgorithm(
  value: string,
): value is EndpointKeyAlgorithm {
  return (ENDPOINT_KEY_ALGORITHMS as readonly string[]).includes(value);
}
