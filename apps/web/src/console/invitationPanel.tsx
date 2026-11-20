/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A local account's invitation: whether one is outstanding, and the controls to
 * send or cancel it.
 *
 * Whether an account may be invited is decided by `invitationRefusal` from
 * `@signet/core`, the same rule the admin API applies, so the button is disabled -
 * with the reason beside it - in exactly the cases the server would refuse. The rule
 * reads the endpoints the account has access to: a password is worth choosing only
 * if one of them signs in with one, so giving access above can be what makes an
 * invitation possible.
 *
 * The link opens the tenant's own invitation page rather than an endpoint's, because
 * the password chosen there is the account's at every endpoint it has access to.
 *
 * Making a new invitation replaces the outstanding one, which is also how a link
 * that was lost before it was sent is dealt with: the server keeps only a hash, so
 * there is nothing to show again.
 *
 * Author: John Grimes
 */

import {
  INVITATION_REFUSAL_MESSAGES,
  INVITATION_TTL_SECONDS,
  invitationRefusal,
} from "@signet/core";
import { useState } from "react";

import { InvitationDialog } from "./invitationDialog.js";
import { useConsoleContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import {
  useCancelInvitation,
  useCreateInvitation,
  useEndUserInvitation,
} from "../api/queries.js";
import {
  DetailList,
  DetailRow,
  ErrorAlert,
  InfoAlert,
  Loading,
  Panel,
} from "../components/layout.js";
import { countOf, formatInstant } from "../formatting/values.js";

import type { EndUserView, IssuedInvitationView } from "../api/types.js";

/** How long a link lasts, in the words the panel uses. */
const LIFETIME = countOf(INVITATION_TTL_SECONDS / 86_400, "day");

interface InvitationPanelProps {
  readonly user: EndUserView;
  /** Whether the reader may send and cancel invitations. */
  readonly mayWrite: boolean;
}

/** The Invitation panel of a local account's detail page. */
export function InvitationPanel({
  user,
  mayWrite,
}: Readonly<InvitationPanelProps>) {
  const { tenant, tenantName } = useConsoleContext();
  const invitation = useEndUserInvitation(tenant, user.id);
  const create = useCreateInvitation(tenant, user.id);
  const cancel = useCancelInvitation(tenant, user.id);
  const [issued, setIssued] = useState<IssuedInvitationView | undefined>();

  const refusal = invitationRefusal(user, user.endpoints);
  const outstanding = invitation.data ?? null;

  return (
    <Panel
      title="Invitation"
      description={`A link that lets the holder of this account choose its password, or reset one they have forgotten. The password works at every endpoint the account has access to. The link works once, for ${LIFETIME}.`}
    >
      {invitation.isPending ? (
        <Loading label="Loading the invitation…" />
      ) : null}
      {invitation.isError ? (
        <ErrorAlert message={describeError(invitation.error)} />
      ) : null}
      {invitation.isSuccess ? (
        <DetailList>
          <DetailRow label="Outstanding invitation">
            {outstanding === null
              ? "None"
              : `Made ${formatInstant(outstanding.createdAt)}, expires ${formatInstant(outstanding.expiresAt)}`}
          </DetailRow>
        </DetailList>
      ) : null}

      {mayWrite ? (
        <>
          {refusal === undefined ? null : (
            <InfoAlert>{INVITATION_REFUSAL_MESSAGES[refusal]}.</InfoAlert>
          )}
          {create.isError ? (
            <ErrorAlert
              message={`The invitation could not be made: ${describeError(create.error)}`}
            />
          ) : null}
          {create.isSuccess && issued === undefined ? (
            <InfoAlert>
              Invitation made. Any earlier link for this account no longer
              works.
            </InfoAlert>
          ) : null}
          {cancel.isError ? (
            <ErrorAlert
              message={`The invitation could not be cancelled: ${describeError(cancel.error)}`}
            />
          ) : null}
          {cancel.isSuccess ? (
            <InfoAlert>
              Invitation cancelled. Its link no longer works.
            </InfoAlert>
          ) : null}

          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              className="btn btn-outline btn-sm"
              disabled={refusal !== undefined || create.isPending}
              onClick={() => {
                cancel.reset();
                create.mutate(undefined, { onSuccess: setIssued });
              }}
            >
              {create.isPending ? (
                <span className="loading loading-spinner loading-xs" />
              ) : null}
              {outstanding === null
                ? "Invite by email"
                : "Send a new invitation"}
            </button>
            {outstanding === null ? null : (
              <button
                type="button"
                className="btn btn-outline btn-error btn-sm"
                disabled={cancel.isPending}
                onClick={() => {
                  create.reset();
                  cancel.mutate();
                }}
              >
                {cancel.isPending ? "Cancelling…" : "Cancel invitation"}
              </button>
            )}
          </div>
        </>
      ) : null}

      {issued === undefined ? null : (
        <InvitationDialog
          invitation={issued}
          username={user.username}
          tenantName={tenantName}
          recipient={user.email}
          onClose={() => {
            setIssued(undefined);
          }}
        />
      )}
    </Panel>
  );
}
