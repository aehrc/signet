/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A newly made invitation link, and the two ways of passing it on.
 *
 * The link is shown here once: the server keeps only its hash, so closing the
 * dialog without sending it means making another. Signet sends no mail, so the
 * dialog offers the administrator's own mail client through a `mailto:` link, and a
 * Copy link button beside it for a machine where no mail client is set up - on such
 * a machine the `mailto:` link does nothing at all, which is why it is not the only
 * way out.
 *
 * The email address is used for the `mailto:` link's recipient and nothing else. It
 * is never sent to Signet and never stored.
 *
 * Author: John Grimes
 */

import { XIcon } from "@primer/octicons-react";
import { useId, useState } from "react";

import { invitationMailto } from "./invitationMailto.js";
import { describeError } from "../api/errors.js";
import { TextField } from "../components/fields.js";
import { ErrorAlert, InfoAlert } from "../components/layout.js";
import { formatInstant } from "../formatting/values.js";

import type { IssuedInvitationView } from "../api/types.js";

/** What the last press of Copy link did. */
type CopyState =
  | { readonly kind: "idle" }
  | { readonly kind: "copied" }
  | { readonly kind: "failed"; readonly cause: string };

interface InvitationDialogProps {
  readonly invitation: IssuedInvitationView;
  readonly username: string;
  readonly endpointName: string;
  readonly onClose: () => void;
}

/** The dialog showing a new invitation link. */
export function InvitationDialog({
  invitation,
  username,
  endpointName,
  onClose,
}: Readonly<InvitationDialogProps>) {
  const headingId = useId();
  const [email, setEmail] = useState("");
  const [copy, setCopy] = useState<CopyState>({ kind: "idle" });

  const copyLink = async () => {
    try {
      // Inside the try because `navigator.clipboard` is absent outside a secure
      // context, and reading a method off it then throws rather than rejecting.
      await navigator.clipboard.writeText(invitation.url);
      setCopy({ kind: "copied" });
    } catch (error) {
      setCopy({ kind: "failed", cause: describeError(error) });
    }
  };

  return (
    <div
      className="modal modal-open"
      role="dialog"
      aria-modal="true"
      aria-labelledby={headingId}
    >
      <div className="modal-box max-w-2xl max-sm:p-4 max-sm:[&_.btn]:min-h-11 max-sm:[&_.btn]:min-w-11">
        <div className="mb-1 flex items-start justify-between gap-4">
          <h2 id={headingId} className="text-lg font-semibold">
            Invitation for {username}
          </h2>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            aria-label="Close"
            onClick={onClose}
          >
            <XIcon />
          </button>
        </div>
        <p className="text-base-content/70 mb-4 text-sm max-sm:text-base">
          Send this link to the person who will use the account. It lets them
          choose a password once, and stops working on{" "}
          {formatInstant(invitation.expiresAt)}. It is shown only now: Signet
          keeps a hash of it, so a lost link is replaced, not recovered.
        </p>

        <div className="flex flex-col gap-4">
          <code className="bg-base-200 rounded-field px-2 py-1 font-mono text-xs break-all">
            {invitation.url}
          </code>

          <TextField
            label="Email address"
            type="email"
            value={email}
            onChange={setEmail}
            autoComplete="off"
            hint="Fills in the recipient of the message. It is not sent to Signet or stored."
          />

          <div className="flex flex-wrap gap-2">
            <a
              className="btn btn-primary btn-sm"
              href={invitationMailto({
                to: email,
                endpointName,
                username,
                url: invitation.url,
                expiresAt: invitation.expiresAt,
              })}
            >
              Open in mail client
            </a>
            <button
              type="button"
              className="btn btn-outline btn-sm"
              onClick={() => {
                void copyLink();
              }}
            >
              Copy link
            </button>
          </div>
          <p className="text-base-content/70 text-sm max-sm:text-base">
            If no message opens, this computer has no mail client set up. Copy
            the link and send it another way.
          </p>

          {copy.kind === "copied" ? (
            <InfoAlert>Link copied to the clipboard.</InfoAlert>
          ) : null}
          {copy.kind === "failed" ? (
            <ErrorAlert message={`The link could not be copied: ${copy.cause}`}>
              <p className="text-sm max-sm:text-base">
                Select it above and copy it by hand.
              </p>
            </ErrorAlert>
          ) : null}
        </div>
      </div>
    </div>
  );
}
