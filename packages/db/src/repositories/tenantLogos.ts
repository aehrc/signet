/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A tenant's logos.
 *
 * A tenant holds at most one logo per variant. The `dark` variant exists only to be
 * shown in place of the `light` one, so it cannot be stored without a `light` logo,
 * and removing the `light` logo removes it too. Neither repository function inspects
 * the bytes: deciding what is an acceptable image is `inspectLogo` in `@signet/core`,
 * and the caller has done it by the time it gets here.
 *
 * Author: John Grimes
 */

import { and, eq } from "drizzle-orm";

import { requireRow } from "./rows.js";
import { executorFor } from "./scope.js";
import { nowValue } from "./time.js";
import { tenantLogos } from "../schema/tenancy.js";

import type { BoundTenantScope } from "./scope.js";
import type { TenantLogo } from "../schema/tenancy.js";
import type { LogoMediaType, LogoVariant, LogoVersion } from "@signet/core";

/** A logo to store. */
export interface TenantLogoInput {
  readonly variant: LogoVariant;
  readonly mediaType: LogoMediaType;
  readonly content: Uint8Array<ArrayBuffer>;
}

/**
 * Stores one of the scoped tenant's logos, replacing any already held.
 *
 * A `dark` variant is refused while the tenant has no `light` logo. The check and the
 * write are separate statements, so a concurrent removal of the `light` logo can
 * leave a `dark` one behind; that row is never shown, because the branding view
 * offers a `dark` variant only beside a `light` one, and the next removal clears it.
 *
 * @param scope - The tenant.
 * @param input - The variant, its media type and its content.
 * @param now - The instant to record as the logo's version; the transaction time
 *   when omitted.
 * @returns The stored row, or undefined when a `dark` variant was refused.
 */
export async function putTenantLogo(
  scope: BoundTenantScope,
  input: TenantLogoInput,
  now?: Date,
): Promise<TenantLogo | undefined> {
  const db = executorFor(scope);
  if (input.variant === "dark") {
    const [light] = await db
      .select({ variant: tenantLogos.variant })
      .from(tenantLogos)
      .where(
        and(
          eq(tenantLogos.tenantId, scope.tenantId),
          eq(tenantLogos.variant, "light"),
        ),
      )
      .limit(1);
    if (light === undefined) {
      return undefined;
    }
  }

  const values = {
    mediaType: input.mediaType,
    content: input.content,
    updatedAt: nowValue(now),
  };
  const rows = await db
    .insert(tenantLogos)
    .values({ ...values, tenantId: scope.tenantId, variant: input.variant })
    .onConflictDoUpdate({
      target: [tenantLogos.tenantId, tenantLogos.variant],
      set: values,
    })
    .returning();
  return requireRow(rows, "upsert into tenant_logos");
}

/**
 * Reads one of the scoped tenant's logos, image included.
 *
 * @param scope - The tenant.
 * @param variant - Which logo.
 * @returns The row, or undefined when the tenant holds no such logo.
 */
export async function getTenantLogo(
  scope: BoundTenantScope,
  variant: LogoVariant,
): Promise<TenantLogo | undefined> {
  const [row] = await executorFor(scope)
    .select()
    .from(tenantLogos)
    .where(
      and(
        eq(tenantLogos.tenantId, scope.tenantId),
        eq(tenantLogos.variant, variant),
      ),
    )
    .limit(1);
  return row;
}

/**
 * Lists the variants the scoped tenant holds, without reading the images.
 *
 * @param scope - The tenant.
 * @returns One entry per stored variant, `light` first.
 */
export async function listTenantLogoVersions(
  scope: BoundTenantScope,
): Promise<readonly LogoVersion[]> {
  return await executorFor(scope)
    .select({
      variant: tenantLogos.variant,
      updatedAt: tenantLogos.updatedAt,
    })
    .from(tenantLogos)
    .where(eq(tenantLogos.tenantId, scope.tenantId))
    // Enum order, which is declaration order: light, then dark.
    .orderBy(tenantLogos.variant);
}

/**
 * Removes one of the scoped tenant's logos.
 *
 * Removing the `light` logo removes the `dark` variant with it, since a variant of
 * nothing would never be shown.
 *
 * @param scope - The tenant.
 * @param variant - Which logo.
 * @returns Whether anything was removed.
 */
export async function deleteTenantLogo(
  scope: BoundTenantScope,
  variant: LogoVariant,
): Promise<boolean> {
  const tenantRows = eq(tenantLogos.tenantId, scope.tenantId);
  const rows = await executorFor(scope)
    .delete(tenantLogos)
    .where(
      variant === "light"
        ? tenantRows
        : and(tenantRows, eq(tenantLogos.variant, variant)),
    )
    .returning({ variant: tenantLogos.variant });
  return rows.length > 0;
}
