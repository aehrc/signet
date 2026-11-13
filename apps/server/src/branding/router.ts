/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The public half of a tenant's branding: what the pages are told, and the logos.
 *
 * Both routes sit under `/t/{tenant}` rather than under an endpoint's issuer, because
 * a logo belongs to the tenant and the console's sidebar shows it too. Neither needs a
 * credential: a logo is put on a login page precisely so that anybody can see it.
 *
 * A logo is served from the same origin as the console, so it is served defensively.
 * Its media type is the one `inspectLogo` sniffed at upload rather than anything the
 * uploader claimed, `nosniff` stops a browser second-guessing it, and a sandboxing
 * content security policy means that an SVG opened directly - rather than through an
 * `<img>`, where script never runs - still cannot run script here. Without that, one
 * tenant's administrator could upload an SVG that acts with the console session of
 * whoever opens it.
 *
 * Author: John Grimes
 */

import {
  isCurrentLogoVersion,
  isLogoVariant,
  tenantBranding,
} from "@signet/core";
import {
  getTenant,
  getTenantLogo,
  listTenantLogoVersions,
  resolveTenantScope,
  withTenantScope,
} from "@signet/db";
import { Hono } from "hono";

import { oauthErrorBody } from "../http/oauthErrors.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { TenantBranding } from "@signet/core";
import type { BoundTenantScope } from "@signet/db";

/** No script, no plugins, no navigation: an image and its own inline styles only. */
const LOGO_CONTENT_SECURITY_POLICY =
  "default-src 'none'; style-src 'unsafe-inline'; sandbox";

/** A year, which is as long as `immutable` is useful for. */
const VERSIONED_LOGO_CACHE = "public, max-age=31536000, immutable";

/**
 * Reads the scoped tenant's branding.
 *
 * @param scope - The tenant, bound.
 * @returns The branding, or null when the tenant holds no logo.
 */
export async function readTenantBranding(
  scope: BoundTenantScope,
): Promise<TenantBranding | null> {
  const tenant = await getTenant(scope);
  if (tenant === undefined) {
    return null;
  }
  return tenantBranding(tenant, await listTenantLogoVersions(scope));
}

/**
 * Builds the router for `/t/:tenantSlug/branding` and `/t/:tenantSlug/logo/:variant`.
 *
 * @param context - The server's dependencies.
 * @returns The router, to be mounted at the root.
 */
export function createBrandingRouter(
  context: ServerContext,
): Hono<SignetEnvironment> {
  const router = new Hono<SignetEnvironment>();
  const noSuchTenant = oauthErrorBody("not_found", "No such tenant");

  router.get("/t/:tenantSlug/branding", async (c) => {
    const scope = await resolveTenantScope(
      context.db,
      c.req.param("tenantSlug"),
    );
    if (scope === undefined) {
      return c.json(noSuchTenant, 404);
    }
    const branding = await withTenantScope(context.db, scope, (bound) =>
      readTenantBranding(bound),
    );
    // Read on every page load, so a new logo appears on the next one.
    c.header("cache-control", "no-cache");
    return c.json({ branding });
  });

  router.get("/t/:tenantSlug/logo/:variant", async (c) => {
    const variant = c.req.param("variant");
    const scope = await resolveTenantScope(
      context.db,
      c.req.param("tenantSlug"),
    );
    if (scope === undefined) {
      return c.json(noSuchTenant, 404);
    }
    const logo = isLogoVariant(variant)
      ? await withTenantScope(context.db, scope, (bound) =>
          getTenantLogo(bound, variant),
        )
      : undefined;
    if (logo === undefined) {
      return c.json(oauthErrorBody("not_found", "No such logo"), 404);
    }

    return c.body(logo.content, 200, {
      "content-type": logo.mediaType,
      "x-content-type-options": "nosniff",
      "content-security-policy": LOGO_CONTENT_SECURITY_POLICY,
      "cache-control": isCurrentLogoVersion(c.req.query("v"), logo.updatedAt)
        ? VERSIONED_LOGO_CACHE
        : "no-cache",
    });
  });

  return router;
}
