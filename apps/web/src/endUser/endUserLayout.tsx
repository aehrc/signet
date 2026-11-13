/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The frame every end-user page sits inside: the branding of the tenant in the URL.
 *
 * One layout route rather than a read in each page, so that every page under an
 * issuer - sign in, picker, consent, manage, the developer portal, the invitation -
 * carries the same mark and the same title without any of them having to remember
 * to ask for it.
 *
 * Author: John Grimes
 */

import { useEffect } from "react";
import { Outlet, useParams } from "react-router";

import { useTenantBranding } from "./queries.js";
import { BrandingContext } from "../components/brandingContext.js";

/**
 * Provides the tenant's branding to the page below it, and titles the window.
 *
 * The title is the tenant's name when it has a logo, and is left as the document's own
 * "Signet" otherwise - including while the branding is still loading.
 */
export function EndUserLayout() {
  const { tenant } = useParams<{ tenant: string }>();
  const branding = useTenantBranding(tenant);
  const name = branding?.name;

  useEffect(() => {
    if (name === undefined) {
      return;
    }
    const previous = document.title;
    document.title = name;
    return () => {
      document.title = previous;
    };
  }, [name]);

  return (
    <BrandingContext value={branding}>
      <Outlet />
    </BrandingContext>
  );
}
