/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The marker in front of one scope in a consent or management list.
 *
 * A write is what a person granting access most needs to notice, so it gets a
 * warning-toned alert icon where a read gets a muted dot. The marker is decorative -
 * the scope's description carries the meaning in words - so it is hidden from
 * assistive technology.
 *
 * It never shrinks. In the flex row a scope is laid out as, a 12px icon is the
 * item a browser squashes first when the description beside it has to wrap, and
 * the difference between the read marker and the write marker is exactly what a
 * person granting access needs to be able to see.
 *
 * Author: John Grimes
 */

import { AlertIcon, DotFillIcon } from "@primer/octicons-react";

interface ScopeMarkerProps {
  /** True when the scope permits writing to the record. */
  readonly writes: boolean;
  /** Layout classes for the wrapper, set by the list the marker sits in. */
  readonly className?: string;
}

/** The bullet in front of a scope: an alert for a write, a dot for a read. */
export function ScopeMarker({ writes, className }: Readonly<ScopeMarkerProps>) {
  // `inline-flex` because Tailwind's preflight makes svg `display: block`, which
  // would otherwise break the line in a list item that is not itself flex.
  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 ${className ?? ""}`.trim()}
    >
      {writes ? (
        <AlertIcon size={12} className="text-warning" />
      ) : (
        <DotFillIcon size={12} className="text-base-content/40" />
      )}
    </span>
  );
}
