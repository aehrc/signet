/**
 * The discovery documents and the JWKS.
 *
 * These three responses are the whole of Signet's public contract with a resource
 * server. Pointing one environment variable at the issuer is the entire
 * integration for Pathling, because Pathling builds its own
 * `.well-known/smart-configuration` by merging fields out of the OpenID Connect
 * discovery document - so `openid-configuration` has to be correct even on an
 * endpoint nobody uses for single sign-on.
 *
 * Nothing here is written by hand. Every field is derived by `@signet/core` from
 * the endpoint's own capability columns, which is what makes the `capabilities`
 * array an accurate statement rather than a hopeful one.
 *
 * Caching is short and explicit. A discovery document that a resource server has
 * cached for a day is a day during which a rotated key or a withdrawn capability
 * has not taken effect; five minutes keeps the documents cheap to serve without
 * making a configuration change effectively irreversible.
 *
 * Author: John Grimes
 */

import {
  buildOpenIdConfiguration,
  buildSmartConfiguration,
} from "@signet/core";
import {
  getEndpointTrustAnchor,
  listPublishableEndpointKeys,
  toCapabilityConfig,
  withTenantScope,
} from "@signet/db";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context } from "hono";

/** How long a relying party may cache a discovery document or the JWKS. */
const CACHE_CONTROL = "public, max-age=300";

/**
 * What the endpoint's opt-in rules add to a discovery document.
 *
 * One lookup, shared by both documents, because the two must answer the same
 * question the same way: a resource server that merges from `openid-configuration`
 * must not be told about a registration endpoint that `smart-configuration` does
 * not advertise.
 *
 * The refusing answer is the one that needs no rule. An endpoint with no trust
 * anchor row advertises no registration endpoint, and there is nothing at
 * `/register` for it to advertise.
 */
async function discoveryRules(
  context: ServerContext,
  c: Context<SignetEnvironment>,
): Promise<{ readonly acceptsVouchedRegistration: boolean }> {
  const { scope } = c.get("issuer");
  const anchor = await withTenantScope(context.db, scope, (bound) =>
    getEndpointTrustAnchor(bound),
  );
  return { acceptsVouchedRegistration: anchor !== undefined };
}

/**
 * Serves `.well-known/smart-configuration`.
 *
 * A factory rather than a plain handler, and asynchronous, because
 * `registration_endpoint` follows the endpoint's trust anchor rule rather than one
 * of its capability columns - and a rule lives in a table of its own.
 *
 * @param context - The server's dependencies.
 */
export function smartConfigurationHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const { endpoint, issuer } = c.get("issuer");
    const rules = await discoveryRules(context, c);
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(
      buildSmartConfiguration(toCapabilityConfig(endpoint, issuer), rules),
    );
  };
}

/**
 * Serves `.well-known/openid-configuration`.
 *
 * A factory rather than a plain handler, and asynchronous, because
 * `id_token_signing_alg_values_supported` is derived from the keys the endpoint
 * actually publishes. Hard-coding the pair SMART names was wrong in both
 * directions: an endpoint signing with something else told relying parties to
 * expect an algorithm they would never see, and a strict verifier configured from
 * this document then rejected every token. Spring Security builds exactly such a
 * verifier, which is how the mismatch was found.
 *
 * @param context - The server's dependencies.
 */
export function openIdConfigurationHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const { endpoint, issuer, scope } = c.get("issuer");
    const keys = await withTenantScope(context.db, scope, (bound) =>
      listPublishableEndpointKeys(bound),
    );
    const rules = await discoveryRules(context, c);
    c.header("Cache-Control", CACHE_CONTROL);
    return c.json(
      buildOpenIdConfiguration(toCapabilityConfig(endpoint, issuer), {
        ...rules,
        signingAlgorithms: advertisedAlgorithms(keys),
      }),
    );
  };
}

/**
 * The distinct algorithms a set of keys uses, in a stable order.
 *
 * Deduplicated because two keys of the same algorithm - which is what a rotation
 * looks like - must not produce a document listing it twice.
 */
function advertisedAlgorithms(
  keys: readonly { readonly algorithm: string }[],
): readonly string[] {
  return [...new Set(keys.map((key) => key.algorithm))];
}

/**
 * Serves the endpoint's JWKS.
 *
 * Both the `active` and the `next` key are published. Publishing `next` ahead of
 * promotion is the whole point of the rotation states: a relying party that caches
 * the JWKS has already seen the incoming key by the time the first token signed
 * with it arrives, so rotation causes no verification failures. Retired keys are
 * excluded - a relying party holding a stale cache will still verify tokens they
 * signed, which is why retirement is a state and not a delete, but the document
 * must stop advertising a key the moment Signet stops signing with it.
 *
 * @param context - The server's dependencies.
 */
export function jwksHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const { scope } = c.get("issuer");
    const keys = await withTenantScope(context.db, scope, (bound) =>
      listPublishableEndpointKeys(bound),
    );

    c.header("Cache-Control", CACHE_CONTROL);
    // `application/jwk-set+json` per RFC 7517 §8.5. Several JWKS clients accept
    // only that or `application/json`, so the more specific one is used.
    c.header("Content-Type", "application/jwk-set+json; charset=UTF-8");
    return c.body(JSON.stringify({ keys: keys.map((key) => key.publicJwk) }));
  };
}
