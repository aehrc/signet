/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The invitation page: where the holder of a new account chooses its password.
 *
 * The same link resets a forgotten password, so nothing here assumes the account is
 * new. The token is in the link's fragment, which the browser never sends to a
 * server; the page reads it and presents it in a request body.
 *
 * The fragment is left in the address bar rather than cleared after reading. Clearing
 * it would make a reload - or a second look after switching tabs to a password
 * manager - land on the invalid-link state with an unspent link, and it buys nothing:
 * a fragment is not sent in requests or in the `Referer` header, and once the link is
 * spent the token in it is worthless.
 *
 * The username is shown prominently, because it is what the reader signs in with
 * afterwards and the link is the only place they are told it.
 *
 * Author: John Grimes
 */

import { END_USER_PASSWORD_MIN_LENGTH } from "@signet/contracts";
import { invitationTokenFromFragment } from "@signet/core";
import { useState } from "react";
import { useLocation, useParams } from "react-router";

import { issuerBase } from "./api.js";
import { passwordChoiceIssues } from "./passwordChoice.js";
import { useAcceptInvitation, useInvitationDetails } from "./queries.js";
import { ApiError, describeError } from "../api/errors.js";
import { CentredShell } from "../components/appShell.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  DetailList,
  DetailRow,
  ErrorAlert,
  Loading,
} from "../components/layout.js";
import { formatInstant } from "../formatting/values.js";

import type { InvitationDetails } from "./api.js";

/** What the page says about a link it cannot use, when the server has not said. */
const INVALID_LINK =
  "This invitation link is not valid. It may have expired, been replaced or already been used.";

/** The invitation page. */
export function InvitationPage() {
  const { tenant, endpoint } = useParams<{
    tenant: string;
    endpoint: string;
  }>();
  // Followed rather than read once: opening a second link in a tab already showing
  // this page changes only the fragment, which does not remount it.
  const token = invitationTokenFromFragment(useLocation().hash);

  if (token === undefined) {
    // No server call: nothing in the fragment could have been a token.
    return <InvalidLink message={INVALID_LINK} />;
  }
  if (tenant === undefined || endpoint === undefined) {
    return <InvalidLink message={INVALID_LINK} />;
  }
  // Keyed on the token so that a new link starts with a fresh lookup and form.
  return (
    <Invitation key={token} tenant={tenant} endpoint={endpoint} token={token} />
  );
}

/** The page proper, once there is a token to ask about. */
function Invitation({
  tenant,
  endpoint,
  token,
}: Readonly<{
  readonly tenant: string;
  readonly endpoint: string;
  readonly token: string;
}>) {
  const details = useInvitationDetails(tenant, endpoint, token);
  const accept = useAcceptInvitation(tenant, endpoint, token);

  if (accept.isSuccess) {
    return (
      <CentredShell
        title="Password set"
        subtitle="Your account is ready. Sign in with your username and the password you just chose."
      >
        <p className="text-sm max-sm:text-base">
          Your username is{" "}
          <code className="font-mono font-semibold">
            {accept.data.username}
          </code>
          .
        </p>
        <div>
          <a
            className="btn btn-primary"
            href={`${issuerBase(tenant, endpoint)}/manage`}
          >
            Sign in
          </a>
        </div>
      </CentredShell>
    );
  }

  if (details.isPending) {
    return (
      <CentredShell title="Choose your password">
        <Loading label="Checking the link…" />
      </CentredShell>
    );
  }

  if (details.error instanceof ApiError && details.error.status === 404) {
    return <InvalidLink message={describeError(details.error)} />;
  }

  if (details.isError) {
    return (
      <CentredShell title="Choose your password">
        <ErrorAlert message={describeError(details.error)} />
      </CentredShell>
    );
  }

  return (
    <ChoosePassword
      details={details.data}
      pending={accept.isPending}
      error={accept.error}
      onSubmit={(password) => {
        accept.mutate(password);
      }}
    />
  );
}

interface ChoosePasswordProps {
  readonly details: InvitationDetails;
  readonly pending: boolean;
  readonly error: unknown;
  readonly onSubmit: (password: string) => void;
}

/** Who the link is for, and the form that spends it. */
function ChoosePassword({
  details,
  pending,
  error,
  onSubmit,
}: Readonly<ChoosePasswordProps>) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  // Problems are shown from the first submit on, not while the first password is
  // still being typed and the confirmation is necessarily different.
  const [submitted, setSubmitted] = useState(false);

  const issues = submitted ? passwordChoiceIssues(password, confirmation) : {};

  return (
    <CentredShell
      title="Choose your password"
      subtitle={`For your account on ${details.endpointName}.`}
    >
      <DetailList>
        <DetailRow label="Name">{details.displayName}</DetailRow>
        <DetailRow label="Username">
          <code className="font-mono font-semibold">{details.username}</code>
        </DetailRow>
        <DetailRow label="Link expires">
          {formatInstant(details.expiresAt)}
        </DetailRow>
      </DetailList>
      <p className="text-base-content/70 text-sm max-sm:text-base">
        You will sign in with this username. The link works once.
      </p>

      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          setSubmitted(true);
          if (
            Object.keys(passwordChoiceIssues(password, confirmation)).length ===
            0
          ) {
            onSubmit(password);
          }
        }}
      >
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          error={issues.password}
          hint={`At least ${String(END_USER_PASSWORD_MIN_LENGTH)} characters.`}
          autoComplete="new-password"
          required
        />
        <TextField
          label="Confirm password"
          type="password"
          value={confirmation}
          onChange={setConfirmation}
          error={issues.confirmation}
          autoComplete="new-password"
          required
        />
        {error === null ? null : <ErrorAlert message={describeError(error)} />}
        <div>
          <SubmitButton pending={pending}>Set password</SubmitButton>
        </div>
      </form>
    </CentredShell>
  );
}

/** What a link that cannot be used looks like. */
function InvalidLink({ message }: Readonly<{ readonly message: string }>) {
  return (
    <CentredShell title="This link does not work" subtitle={message}>
      <p className="text-sm max-sm:text-base">
        Ask whoever sent it to send you a new invitation.
      </p>
    </CentredShell>
  );
}
