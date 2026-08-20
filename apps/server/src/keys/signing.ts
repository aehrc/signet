/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Signing tokens with an endpoint's active key.
 *
 * The claims are assembled by `@signet/core` and arrive here complete: this
 * module adds a protected header and a signature and nothing else. That division
 * is deliberate - the console's policy simulator calls the same assembly
 * functions and shows the operator exactly the payload that would be signed, and
 * it could not if any claim were added at signing time.
 *
 * A key is loaded per issuance rather than cached. An endpoint's active key can be
 * rotated or retired at any moment, and a cached key would keep signing with a
 * withdrawn one - which, for the suspected-compromise case that retirement
 * exists to serve, is the only failure that matters. The cost is one indexed read
 * against a table holding a handful of rows per endpoint.
 *
 * Author: John Grimes
 */

import { getActiveEndpointKey, withTenantScope } from "@signet/db";
import { SignJWT } from "jose";

import { isEndpointKeyAlgorithm } from "./algorithms.js";
import { importPrivateEndpointKey } from "./material.js";

import type { EndpointKeyAlgorithm } from "./algorithms.js";
import type { Database, EndpointKey, EndpointScope } from "@signet/db";
import type { CryptoKey as JoseCryptoKey } from "jose";

/** An endpoint's active key, loaded and ready to sign. */
export interface LoadedSigningKey {
  readonly kid: string;
  readonly algorithm: EndpointKeyAlgorithm;
  readonly key: JoseCryptoKey;
}

/** Why an endpoint could not sign. */
export type SigningKeyRefusal =
  /** The endpoint has no `active` key. Nothing can be issued until it does. */
  | "no-active-key"
  /** The stored algorithm is not one Signet signs with. */
  | "unsupported-algorithm";

/** The outcome of loading a signing key. */
export type SigningKeyLoad =
  | { readonly ok: true; readonly signingKey: LoadedSigningKey }
  | { readonly ok: false; readonly reason: SigningKeyRefusal };

/**
 * Prepares a stored key row for signing.
 *
 * Separate from the query, so the decrypt-and-import step is testable against a
 * row built in memory.
 *
 * @param row - The `endpoint_keys` row to use.
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 */
export async function prepareSigningKey(
  row: EndpointKey,
  masterKey: string,
): Promise<SigningKeyLoad> {
  // The algorithm is taken from its own column, not from the encrypted JWK's own
  // `alg`: the column is what the rest of the system agrees on, and letting the
  // blob describe itself would mean a rewritten row could change how it is used.
  if (!isEndpointKeyAlgorithm(row.algorithm)) {
    return { ok: false, reason: "unsupported-algorithm" };
  }

  return {
    ok: true,
    signingKey: {
      kid: row.kid,
      algorithm: row.algorithm,
      key: await importPrivateEndpointKey(
        row.privateJwkEncrypted,
        row.algorithm,
        masterKey,
      ),
    },
  };
}

/**
 * Loads the endpoint's active signing key.
 *
 * @param db - The connection to read through.
 * @param scope - Proof of which endpoint is being asked about.
 * @param masterKey - The `SIGNET_MASTER_KEY` value.
 */
export async function loadSigningKey(
  db: Database,
  scope: EndpointScope,
  masterKey: string,
): Promise<SigningKeyLoad> {
  const row = await withTenantScope(db, scope, (bound) =>
    getActiveEndpointKey(bound),
  );
  return row === undefined
    ? { ok: false, reason: "no-active-key" }
    : await prepareSigningKey(row, masterKey);
}

/**
 * Signs a fully assembled claim set.
 *
 * @param claims - The complete payload. Nothing is added to it.
 * @param signingKey - The endpoint's active key.
 * @param type - The `typ` header. Defaults to `JWT`; RFC 9068's `at+jwt` is
 *   available for a resource server that requires it, but is not the default,
 *   because several FHIR servers reject a `typ` they do not recognise.
 */
export async function signClaims(
  claims: Readonly<Record<string, unknown>>,
  signingKey: LoadedSigningKey,
  type = "JWT",
): Promise<string> {
  return await new SignJWT(claims)
    .setProtectedHeader({
      alg: signingKey.algorithm,
      kid: signingKey.kid,
      typ: type,
    })
    .sign(signingKey.key);
}
