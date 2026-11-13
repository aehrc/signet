/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * What the end-user pages are told about a tenant's branding.
 *
 * A tenant is branded exactly when it holds a logo. Without one the pages carry the
 * Signet wordmark and title as they always have, and nothing about the tenant - not
 * even its name - is shown, because a name an operator chose for the console may not
 * be one they meant a patient to read.
 *
 * Each logo's URL carries the instant it was stored, so the image behind any one URL
 * never changes. That lets the logo route tell a browser to cache it indefinitely, and
 * a replacement is seen straight away because it is handed out under a new URL.
 *
 * Author: John Grimes
 */

import type { LogoVariant } from "./logo.js";

/** A tenant's branding, as the pages render it. */
export interface TenantBranding {
  /** The tenant's name: the logo's alternative text and the pages' title. */
  readonly name: string;
  /** Where the logo is served, on the same origin. */
  readonly logoUrl: string;
  /** Where the dark-scheme variant is served, or null when there is none. */
  readonly darkLogoUrl: string | null;
}

/** Which logo variants a tenant holds, and when each was stored. */
export interface LogoVersion {
  readonly variant: LogoVariant;
  readonly updatedAt: Date;
}

/** The URL a logo is served from, versioned by when it was stored. */
function logoUrl(slug: string, version: LogoVersion): string {
  return `/t/${encodeURIComponent(slug)}/logo/${version.variant}?v=${String(version.updatedAt.getTime())}`;
}

/**
 * Builds a tenant's branding from the logos it holds.
 *
 * @param tenant - The tenant.
 * @param tenant.slug - Its `/t/{slug}` path segment, which the logo URLs are under.
 * @param tenant.name - Its name, which the pages show.
 * @param versions - The logo variants the tenant holds, as listed from storage.
 * @returns The branding, or null when the tenant holds no logo. A dark variant with no
 *   logo beside it is ignored rather than shown on its own.
 * @example
 * ```ts
 * tenantBranding({ slug: "acme", name: "Acme Health" }, [
 *   { variant: "light", updatedAt: new Date(1_772_323_200_000) },
 * ]);
 * // { name: "Acme Health", logoUrl: "/t/acme/logo/light?v=1772323200000",
 * //   darkLogoUrl: null }
 * ```
 */
export function tenantBranding(
  tenant: { readonly slug: string; readonly name: string },
  versions: readonly LogoVersion[],
): TenantBranding | null {
  const light = versions.find((version) => version.variant === "light");
  if (light === undefined) {
    return null;
  }
  const dark = versions.find((version) => version.variant === "dark");
  return {
    name: tenant.name,
    logoUrl: logoUrl(tenant.slug, light),
    darkLogoUrl: dark === undefined ? null : logoUrl(tenant.slug, dark),
  };
}

/**
 * Whether a logo request names the version currently stored.
 *
 * Only then may the response be cached indefinitely: any other request - an old
 * version, or none at all - could be answered by an image that is about to change.
 *
 * @param requested - The `v` query parameter, if the request carried one.
 * @param updatedAt - When the stored logo was written.
 * @returns True when the request names the stored version.
 */
export function isCurrentLogoVersion(
  requested: string | undefined,
  updatedAt: Date,
): boolean {
  return requested === String(updatedAt.getTime());
}
