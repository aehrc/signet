/**
 * The account menu in the console header.
 *
 * The header used to show an email and a sign-out button side by side, which was
 * fine while signing out was the only thing a person could do to their own account.
 * Passkeys are the second, and a second bare button in the header would start a
 * pattern that ends with five of them, so the two are gathered under the name of
 * whoever is signed in.
 *
 * A personal access token has no account menu to open - it is not a person, holds no
 * password and cannot manage passkeys - so it gets the sign-out button on its own.
 *
 * Author: John Grimes
 */

import type { ReactNode } from "react";

interface AccountMenuProps {
  /** What to show as the menu's label: an email, or a token's name. */
  readonly label: string;
  /** Opens the passkey dialog. Absent for a caller who is not a person. */
  readonly onManagePasskeys?: () => void;
  readonly onSignOut: () => void;
  /** True while the sign-out request is in flight. */
  readonly signingOut: boolean;
}

/** The trigger and its menu, or a bare sign-out button where there is no menu. */
export function AccountMenu({
  label,
  onManagePasskeys,
  onSignOut,
  signingOut,
}: Readonly<AccountMenuProps>): ReactNode {
  if (onManagePasskeys === undefined) {
    return (
      <>
        <span className="text-base-content/60 hidden text-xs sm:inline">
          {label}
        </span>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={signingOut}
          onClick={onSignOut}
        >
          Sign out
        </button>
      </>
    );
  }

  return (
    <div className="dropdown dropdown-end">
      <button
        type="button"
        // daisyUI's dropdown opens on focus, so the trigger has to be focusable
        // and has to say what it does - "alex@example.org" alone tells a screen
        // reader nothing about what pressing it will reveal.
        className="btn btn-ghost btn-sm max-w-48"
        aria-label={`Account menu for ${label}`}
      >
        <span className="truncate">{label}</span>
        <span aria-hidden="true">▾</span>
      </button>
      <ul className="dropdown-content menu bg-base-100 rounded-box border-base-300 z-10 mt-1 w-52 border p-2 shadow">
        <li>
          <button type="button" onClick={onManagePasskeys}>
            Passkeys
          </button>
        </li>
        <li>
          <button type="button" disabled={signingOut} onClick={onSignOut}>
            Sign out
          </button>
        </li>
      </ul>
    </div>
  );
}
