/**
 * Generation and protection of an endpoint's signing keys.
 *
 * Each endpoint signs with its own key, which is the point of the per-endpoint
 * issuer: a tenant's tokens cannot be forged by another tenant even in the event
 * that Signet itself is compromised in one endpoint's favour, and rotating one
 * endpoint's key affects nobody else.
 *
 * The private half is envelope-encrypted under `SIGNET_MASTER_KEY` before it
 * reaches the database, and this module is the only place that decrypts it. No
 * API returns it, and the value handed to the data layer is already ciphertext -
 * so a repository, a logical dump and a Drizzle log all see the same opaque
 * string.
 *
 * SMART requires RS384 or ES384 for client assertions, and Signet signs its own
 * tokens with the same pair of algorithms so that a resource server verifying
 * Signet's tokens needs no configuration it does not already have.
 *
 * Author: John Grimes
 */

import { decryptSecret, encryptSecret } from "@signet/db";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";

import type { EndpointKeyAlgorithm } from "./algorithms.js";
import type { CryptoKey as JoseCryptoKey, JWK } from "jose";

/** A freshly generated key pair, ready to be stored. */
export interface GeneratedEndpointKey {
  /**
   * The RFC 7638 JWK thumbprint.
   *
   * Derived from the key rather than random, so that the same key always has the
   * same identifier - which makes a `kid` collision within an endpoint mean
   * "this key is already published", not "bad luck".
   */
  readonly kid: string;
  readonly algorithm: EndpointKeyAlgorithm;
  /** Served verbatim from the endpoint's JWKS. Carries `kid`, `alg` and `use`. */
  readonly publicJwk: Record<string, unknown>;
  /** Envelope ciphertext, safe to store and to include in a dump. */
  readonly privateJwkEncrypted: string;
}

/**
 * Generates a signing key pair for an endpoint.
 *
 * The keys are extractable, because the private half has to be serialised to be
 * stored at all - an endpoint's key must survive a pod restart, and a
 * non-extractable key could not.
 *
 * @param algorithm - `RS384` or `ES384`.
 * @param masterKey - The `SIGNET_MASTER_KEY` value protecting the private half.
 */
export async function generateEndpointKey(
  algorithm: EndpointKeyAlgorithm,
  masterKey: string,
): Promise<GeneratedEndpointKey> {
  const { publicKey, privateKey } = await generateKeyPair(algorithm, {
    extractable: true,
  });

  const publicJwk = await exportJWK(publicKey);
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(publicJwk);

  return {
    kid,
    algorithm,
    // `alg` and `use` are published so a relying party need not infer them from
    // the key type: an EC key alone does not say whether it is P-384 for ES384 or
    // for ECDH, and a JWKS consumer that has to guess will eventually guess wrong.
    publicJwk: { ...publicJwk, kid, alg: algorithm, use: "sig" },
    privateJwkEncrypted: await encryptSecret(
      JSON.stringify({ ...privateJwk, kid, alg: algorithm }),
      masterKey,
    ),
  };
}

/**
 * Recovers a stored private key for signing.
 *
 * @param ciphertext - The `private_jwk_encrypted` column value.
 * @param algorithm - The key's algorithm, from its own column rather than from
 *   the JWK's `alg`: the column is what the rest of the system agrees on, and
 *   trusting the encrypted blob's own claim about itself would let a rewritten row
 *   change the signing algorithm.
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 * @throws {EnvelopeError} When the ciphertext cannot be decrypted, which means
 *   the master key has changed or the row has been tampered with. Both are
 *   operational emergencies rather than request-level failures, so neither is
 *   flattened into a return value.
 */
export async function importPrivateEndpointKey(
  ciphertext: string,
  algorithm: EndpointKeyAlgorithm,
  masterKey: string,
): Promise<JoseCryptoKey> {
  const decrypted = await decryptSecret(ciphertext, masterKey);
  const jwk = JSON.parse(decrypted) as JWK;
  const key = await importJWK(jwk, algorithm);
  if (!(key instanceof CryptoKey)) {
    // `importJWK` returns bytes for a symmetric key. Reaching here means a
    // symmetric secret was stored where an asymmetric key belongs, which would
    // otherwise fail later with a much less specific message.
    throw new TypeError(
      `endpoint key ${String(jwk.kid)} is not an asymmetric key`,
    );
  }
  return key;
}
