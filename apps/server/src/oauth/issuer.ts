/**
 * Resolution of the endpoint an OAuth request is addressed to.
 *
 * Every OAuth route lives under `/t/{tenant}/e/{endpoint}`, and that prefix *is*
 * the issuer identifier: the string published as `issuer` in both discovery
 * documents, minted into every token's `iss`, and compared byte-for-byte by
 * relying parties. Deriving it in one place, from the same configured public URL
 * the routes are mounted under, is what stops the advertised issuer from drifting
 * away from the URL that actually serves it.
 *
 * The middleware also converts the path into an `EndpointScope`, which is the
 * capability every tenant-scoped query in `@signet/db` requires. A handler under
 * this middleware therefore cannot read another tenant's rows: it has no scope
 * naming one.
 */

import { endpointUrls, normaliseIssuer } from "@signet/core";
import { resolveIssuer } from "@signet/db";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { MiddlewareHandler } from "hono";

/**
 * Builds an endpoint's issuer identifier.
 *
 * @param publicUrl - The deployment's public origin, without a trailing slash.
 * @param tenantSlug - The tenant's URL segment.
 * @param endpointSlug - The endpoint's URL segment.
 */
export function issuerFor(
  publicUrl: string,
  tenantSlug: string,
  endpointSlug: string,
): string {
  return `${normaliseIssuer(publicUrl)}/t/${tenantSlug}/e/${endpointSlug}`;
}

/** The path prefix every endpoint-scoped route is mounted under. */
export const ISSUER_PATH_PREFIX = "/t/:tenantSlug/e/:endpointSlug";

/**
 * Resolves `:tenantSlug` and `:endpointSlug` into a scope, or answers 404.
 *
 * A 404 is the right answer for an unknown endpoint, and deliberately the same
 * answer for an unknown tenant: distinguishing them would let an unauthenticated
 * caller enumerate which tenants exist on a shared deployment.
 *
 * @param context - The server's dependencies.
 */
export function withIssuer(
  context: ServerContext,
): MiddlewareHandler<SignetEnvironment> {
  return async (c, next) => {
    const tenantSlug = c.req.param("tenantSlug");
    const endpointSlug = c.req.param("endpointSlug");

    const resolved =
      tenantSlug === undefined || endpointSlug === undefined
        ? undefined
        : await resolveIssuer(context.db, tenantSlug, endpointSlug);

    if (resolved === undefined) {
      return c.json(
        { error: "not_found", error_description: "No such endpoint" },
        404,
      );
    }

    const issuer = issuerFor(
      context.config.publicUrl,
      resolved.tenant.slug,
      resolved.endpoint.slug,
    );

    c.set("issuer", {
      issuer,
      urls: endpointUrls(issuer),
      scope: resolved.scope,
      tenant: resolved.tenant,
      endpoint: resolved.endpoint,
    });

    await next();
    return;
  };
}
