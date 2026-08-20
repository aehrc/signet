/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Checking that a trusted issuer signed what somebody presented.
 *
 * Two surfaces need this and they need it identically: `/register` verifies a
 * software statement against a trust anchor's published keys, and the token
 * endpoint verifies a permission ticket against a ticket issuer's. Both fetch the
 * keys through the outbound guard, both refuse rather than fall back when the
 * fetch fails, and both hold the signature to a closed set of asymmetric
 * algorithms. A second implementation would eventually accept a ticket that the
 * registration endpoint would have refused.
 *
 * **Signature only.** Everything temporal is decided by the pure validation that
 * follows, so that "the issuer did not sign this" and "the issuer signed this a
 * week ago" are distinguishable refusals rather than one opaque failure.
 *
 * Author: John Grimes
 */

import { compactVerify, createLocalJWKSet, decodeProtectedHeader } from "jose";

import { resolveRemoteJwks } from "./remoteJwks.js";

import type { ServerContext } from "../context.js";

/** What one verification is about. */
export interface TrustedJwsVerification {
  /** Where the issuer publishes its keys. Administrator-supplied, hence guarded. */
  readonly jwksUri: string;
  /** The compact JWS presented. */
  readonly token: string;
  /** The algorithms the signature may use. */
  readonly algorithms: readonly string[];
  /** What to call the token in a refusal, e.g. `permission ticket`. */
  readonly noun: string;
}

/** The outcome of a verification. */
export type TrustedJwsResult =
  | { readonly ok: true; readonly claims: unknown }
  | { readonly ok: false; readonly description: string };

/**
 * Verifies a compact JWS against the keys its issuer currently publishes.
 *
 * @param context - The server's dependencies, for the key cache and the guard.
 * @param verification - The address to fetch, the token, the permitted
 *   algorithms, and what to call the token in a refusal.
 * @returns The decoded claims, or why the token was refused. An issuer that
 *   cannot be reached has vouched for nothing, and treating its silence as
 *   assent is the mistake both callers exist to avoid.
 * @example
 * ```ts
 * const verified = await verifyTrustedJws(context, {
 *   jwksUri: rule.jwksUri,
 *   token: presented,
 *   algorithms: PERMITTED_TICKET_ALGORITHMS,
 *   noun: "permission ticket",
 * });
 * ```
 */
export async function verifyTrustedJws(
  context: ServerContext,
  verification: TrustedJwsVerification,
): Promise<TrustedJwsResult> {
  const { noun, token } = verification;

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(token).kid;
  } catch {
    return { ok: false, description: `The ${noun} has no header` };
  }

  const resolved = await resolveRemoteJwks({
    jwksUri: verification.jwksUri,
    cache: context.jwksCache,
    now: context.clock(),
    allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
    ...(kid === undefined ? {} : { kid }),
  });
  if (!resolved.ok) {
    return { ok: false, description: resolved.description };
  }

  try {
    const verified = await compactVerify(
      token,
      createLocalJWKSet(resolved.keys),
      { algorithms: [...verification.algorithms] },
    );
    return {
      ok: true,
      claims: JSON.parse(new TextDecoder().decode(verified.payload)) as unknown,
    };
  } catch {
    return {
      ok: false,
      description: `The ${noun}'s signature could not be verified against the issuer's published keys`,
    };
  }
}
