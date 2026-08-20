/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Tenant settings.
 *
 * Only the display name is editable. The slug is part of every endpoint issuer
 * under the tenant - `/t/{tenant}/e/{endpoint}` - so changing it would invalidate
 * the `iss` of every token already issued, every registered app's configuration and
 * every FHIR server pointed at one of those endpoints. It is therefore absent from
 * the schema rather than guarded in a handler.
 *
 * Author: John Grimes
 */

import { z } from "zod";

/** Editing a tenant. */
export const tenantPatchSchema = z.object({
  name: z.string().min(1).max(200).optional(),
});

export type TenantPatch = z.infer<typeof tenantPatchSchema>;
