/**
 * The management page: what an end user has granted, and how to take it back.
 *
 * This is SMART's `management_endpoint`, which the discovery document advertises so an
 * app can link a patient to it. Its audience is the person whose record is being shared,
 * so it describes each app's access in sentences rather than in scopes, and says plainly
 * what withdrawing does.
 *
 * A 401 is not an error here: it is the page discovering that nobody is signed in, which
 * is the ordinary way of arriving. So it renders the sign-in form rather than a failure.
 *
 * Withdrawn entries stay on the list, marked. Removing them would look, to somebody who
 * had just withdrawn access, like the record had been lost rather than ended.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { useParams } from "react-router";

import { describeEntry } from "./accessWording.js";
import {
  useAuthorizations,
  useManageSignIn,
  useManageSignOut,
  useRevokeAuthorization,
} from "./queries.js";
import { describeScopes } from "./scopeDescriptions.js";
import { describeError, isUnauthenticated } from "../api/errors.js";
import { CentredShell } from "../components/appShell.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  Panel,
} from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { countOf } from "../formatting/values.js";

/** The management page. */
export function ManagePage() {
  const { tenant, endpoint } = useParams<{
    tenant: string;
    endpoint: string;
  }>();

  if (tenant === undefined || endpoint === undefined) {
    return (
      <CentredShell title="Not found">
        <p className="text-base-content/70 text-sm">
          This page belongs to a particular endpoint. Follow the link your app
          or your provider gave you.
        </p>
      </CentredShell>
    );
  }

  return <Authorizations tenant={tenant} endpoint={endpoint} />;
}

/** The page proper, once the endpoint is known. */
function Authorizations({
  tenant,
  endpoint,
}: Readonly<{ readonly tenant: string; readonly endpoint: string }>) {
  const view = useAuthorizations(tenant, endpoint);
  const signOut = useManageSignOut(tenant, endpoint);
  const revoke = useRevokeAuthorization(tenant, endpoint);

  if (view.isPending) {
    return (
      <CentredShell title="Your app access">
        <Loading />
      </CentredShell>
    );
  }

  // Not an error: this is how arriving without a session looks.
  if (isUnauthenticated(view.error)) {
    return <SignInPanel tenant={tenant} endpoint={endpoint} />;
  }

  if (view.isError || view.data === undefined) {
    return (
      <CentredShell title="Your app access">
        <ErrorAlert message={describeError(view.error)} />
      </CentredShell>
    );
  }

  const data = view.data;
  const liveTokens = data.liveTokens.access + data.liveTokens.refresh;

  return (
    <div className="bg-base-200 min-h-screen p-6">
      <div className="mx-auto max-w-3xl">
        <header className="mb-6 flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-xl font-bold">Signet</p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight">
              Your app access
            </h1>
            <p className="text-base-content/70 mt-1 text-sm">
              Signed in as {data.user.displayName}. These are the apps you have
              allowed to use your record.
            </p>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            disabled={signOut.isPending}
            onClick={() => {
              signOut.mutate();
            }}
          >
            Sign out
          </button>
        </header>

        {revoke.isError ? (
          <ErrorAlert message={describeError(revoke.error)} />
        ) : null}

        {data.authorizations.length === 0 ? (
          <Panel>
            <EmptyState
              title="No apps have access"
              description="When you allow an app to use your record it appears here, and you can withdraw it at any time."
            />
          </Panel>
        ) : (
          data.authorizations.map((authorization) => (
            <Panel
              key={
                authorization.consentId ?? `tokens-${authorization.clientId}`
              }
              title={authorization.clientName}
              description={describeEntry(authorization)}
              actions={
                authorization.active ? (
                  <button
                    type="button"
                    className="btn btn-outline btn-error btn-sm"
                    disabled={revoke.isPending}
                    onClick={() => {
                      if (
                        globalThis.confirm(
                          `Withdraw ${authorization.clientName}'s access? It will stop working immediately, and will have to ask again.`,
                        )
                      ) {
                        revoke.mutate(authorization.clientId);
                      }
                    }}
                  >
                    Withdraw access
                  </button>
                ) : (
                  <StatusBadge tone="neutral">withdrawn</StatusBadge>
                )
              }
            >
              <ul className="flex flex-col gap-1">
                {describeScopes(authorization.scope).map((described) => (
                  <li key={described.scope} className="text-sm">
                    <span aria-hidden="true" className="mr-2">
                      {described.writes ? "⚠" : "•"}
                    </span>
                    {described.description}
                  </li>
                ))}
              </ul>
            </Panel>
          ))
        )}

        {liveTokens > 0 ? (
          <InfoAlert>
            Apps currently hold{" "}
            {countOf(data.liveTokens.access, "access token")} and{" "}
            {countOf(data.liveTokens.refresh, "refresh token")} issued for you.
            Withdrawing an app&apos;s access revokes the ones it holds
            immediately.
          </InfoAlert>
        ) : null}
      </div>
    </div>
  );
}

/** Signing in to the management page. */
function SignInPanel({
  tenant,
  endpoint,
}: Readonly<{ readonly tenant: string; readonly endpoint: string }>) {
  const signIn = useManageSignIn(tenant, endpoint);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  return (
    <CentredShell
      title="Your app access"
      subtitle="Sign in to see which apps can use your record, and to withdraw any of them."
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          signIn.mutate({ username, password });
        }}
      >
        <TextField
          label="Username"
          value={username}
          onChange={setUsername}
          autoComplete="username"
          required
        />
        <TextField
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          required
        />
        {signIn.error === null ? null : (
          <ErrorAlert message={describeError(signIn.error)} />
        )}
        <div>
          <SubmitButton pending={signIn.isPending}>Sign in</SubmitButton>
        </div>
      </form>
    </CentredShell>
  );
}
