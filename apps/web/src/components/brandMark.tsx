/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The mark at the top of every page: a tenant's logo, or the Signet wordmark.
 *
 * Author: John Grimes
 */

import { use } from "react";

import { BrandingContext } from "./brandingContext.js";

interface BrandMarkProps {
  /** Classes for the box the mark sits in, typically its alignment. */
  readonly className?: string;
}

/**
 * The tenant's logo, or the Signet wordmark when the page carries no branding.
 * Which applies is read from {@link BrandingContext}.
 *
 * The box is the same height in every state, so the page does not jump when a logo
 * arrives. While the branding loads the box is empty: showing the wordmark first
 * would flash Signet's name on a page that is about to carry somebody else's.
 */
export function BrandMark({ className = "" }: Readonly<BrandMarkProps>) {
  const branding = use(BrandingContext);
  const box = `flex h-10 items-center ${className}`;

  if (branding === undefined) {
    return <div className={box} aria-hidden="true" />;
  }
  if (branding === null) {
    return (
      <div className={box}>
        <p className="text-xl font-bold">Signet</p>
      </div>
    );
  }
  return (
    <div className={box}>
      <picture>
        {branding.darkLogoUrl === null ? null : (
          <source
            srcSet={branding.darkLogoUrl}
            media="(prefers-color-scheme: dark)"
          />
        )}
        <img
          src={branding.logoUrl}
          alt={branding.name}
          className="h-10 w-auto max-w-full object-contain"
        />
      </picture>
    </div>
  );
}
