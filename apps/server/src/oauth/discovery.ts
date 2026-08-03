/**
 * The discovery documents and the JWKS.
 *
 * These three responses are the whole of Signet's public contract with a resource
 * server. Pointing one environment variable at the issuer is the entire
 * integration for Pathling, because Pathling builds its own
 * `.well-known/smart-configuration` by merging fields out of the OpenID Connect
 * discovery document — so `openid-configuration` has to be correct even on an
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
 */

import {
  buildOpenIdConfiguration,
  buildSmartConfiguration,
} from "@signet/core";
import { listPublishableEndpointKeys, toCapabilityConfig } from "@signet/db";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context } from "hono";

/** How long a relying party may cache a discovery document or the JWKS. */
const CACHE_CONTROL = "public, max-age=300";

/**
 * Serves `.well-known/smart-configuration`.
 *
 * A plain handler rather than a factory: unlike the JWKS it needs nothing from the
 * server context, because everything it publishes is derived from the endpoint row
 * the issuer middleware already resolved.
 */
export function smartConfigurationHandler(c: Context<SignetEnvironment>) {
  const { endpoint, issuer } = c.get("issuer");
  c.header("Cache-Control", CACHE_CONTROL);
  return c.json(buildSmartConfiguration(toCapabilityConfig(endpoint, issuer)));
}

/** Serves `.well-known/openid-configuration`. */
export function openIdConfigurationHandler(c: Context<SignetEnvironment>) {
  const { endpoint, issuer } = c.get("issuer");
  c.header("Cache-Control", CACHE_CONTROL);
  return c.json(buildOpenIdConfiguration(toCapabilityConfig(endpoint, issuer)));
}

/**
 * Serves the endpoint's JWKS.
 *
 * Both the `active` and the `next` key are published. Publishing `next` ahead of
 * promotion is the whole point of the rotation states: a relying party that caches
 * the JWKS has already seen the incoming key by the time the first token signed
 * with it arrives, so rotation causes no verification failures. Retired keys are
 * excluded — a relying party holding a stale cache will still verify tokens they
 * signed, which is why retirement is a state and not a delete, but the document
 * must stop advertising a key the moment Signet stops signing with it.
 *
 * @param context - The server's dependencies.
 */
export function jwksHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const { scope } = c.get("issuer");
    const keys = await listPublishableEndpointKeys(context.db, scope);

    c.header("Cache-Control", CACHE_CONTROL);
    // `application/jwk-set+json` per RFC 7517 §8.5. Several JWKS clients accept
    // only that or `application/json`, so the more specific one is used.
    c.header("Content-Type", "application/jwk-set+json; charset=UTF-8");
    return c.body(JSON.stringify({ keys: keys.map((key) => key.publicJwk) }));
  };
}
