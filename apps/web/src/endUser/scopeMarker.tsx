/**
 * The marker in front of one scope in a consent or management list.
 *
 * A write is what a person granting access most needs to notice, so it gets a
 * warning-toned alert icon where a read gets a muted dot. The marker is decorative -
 * the scope's description carries the meaning in words - so it is hidden from
 * assistive technology.
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
      className={`inline-flex ${className ?? ""}`.trim()}
    >
      {writes ? (
        <AlertIcon size={12} className="text-warning" />
      ) : (
        <DotFillIcon size={12} className="text-base-content/40" />
      )}
    </span>
  );
}
