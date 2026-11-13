/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The branding a page carries, as React context.
 *
 * Which branding is decided by whoever renders the page: the end-user layout provides
 * the branding of the tenant in the URL, the console provides the branding of the
 * tenant being administered, and anything that provides nothing - the console's
 * sign-in page, which belongs to no tenant - keeps the Signet wordmark. Reading it
 * from context rather than a prop means the shells and headers that draw the mark
 * need not be told about tenants at all.
 *
 * Author: John Grimes
 */

import { createContext } from "react";

import type { TenantBranding } from "@signet/core";

/**
 * The branding the page carries.
 *
 * Null for the Signet wordmark, which is also the default, and undefined while a
 * tenant's branding is still being read.
 */
export const BrandingContext = createContext<TenantBranding | null | undefined>(
  null,
);
