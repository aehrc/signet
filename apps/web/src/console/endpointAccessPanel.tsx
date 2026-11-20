/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Which of the tenant's endpoints an account may sign in at.
 *
 * Access is explicit, endpoint by endpoint: an account with no access to an endpoint
 * cannot sign in there, is not offered there as a persona, and has its refresh
 * tokens refused there. So every endpoint of the tenant gets a row, with the control
 * to give or withdraw access, rather than a list of only the endpoints already
 * given - an endpoint missing from the list would be one nobody thought to grant.
 *
 * Withdrawing is destructive in a way the button alone does not say: the server
 * deletes the account's consents and sessions on that endpoint, and its refresh
 * tokens there stop working. It asks first, with a native confirm, as every other
 * destructive action in the console does, and says exactly that.
 *
 * On a SMART endpoint the account has access to, the row also holds the `fhirUser`
 * reference and, for a persona, the default launch context. Both name resources on
 * that endpoint's FHIR server, which is why they are set here rather than on the
 * account. An OAuth endpoint has neither.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { useConsoleContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useEndpoints,
  useGrantEndpointAccess,
  useRevokeEndpointAccess,
} from "../api/queries.js";
import { SaveOutcome, SaveRow, TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  Panel,
} from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { endpointKindLabel } from "../formatting/endpointKind.js";
import { formatInstant } from "../formatting/values.js";
import {
  endpointAccessBody,
  endpointAccessFormValues,
  endpointAccessRows,
} from "../forms/endUserEdit.js";

import type {
  EndpointAccessView,
  EndpointView,
  EndUserView,
} from "../api/types.js";

interface EndpointAccessPanelProps {
  readonly user: EndUserView;
  /** Whether the reader may give and withdraw access. */
  readonly mayWrite: boolean;
}

/** The Endpoint access panel of a user's detail page. */
export function EndpointAccessPanel({
  user,
  mayWrite,
}: Readonly<EndpointAccessPanelProps>) {
  const { tenant } = useConsoleContext();
  const endpoints = useEndpoints(tenant);

  return (
    <Panel
      title="Endpoint access"
      description="This account signs in only at the endpoints it has been given access to. The same username and password work at each of them."
    >
      {endpoints.isPending ? (
        <Loading label="Loading the tenant's endpoints…" />
      ) : null}
      {endpoints.isError ? (
        <ErrorAlert message={describeError(endpoints.error)} />
      ) : null}
      {endpoints.data?.length === 0 ? (
        <EmptyState
          title="No endpoints"
          description="This tenant has no endpoints yet, so there is nowhere to give this account access to."
        />
      ) : null}
      {endpointAccessRows(endpoints.data ?? [], user.endpoints).map((row) => (
        <EndpointAccessRow
          key={row.endpoint.slug}
          user={user}
          endpoint={row.endpoint}
          access={row.access}
          mayWrite={mayWrite}
        />
      ))}
    </Panel>
  );
}

interface EndpointAccessRowProps {
  readonly user: EndUserView;
  readonly endpoint: EndpointView;
  /** Undefined when the account has no access to the endpoint. */
  readonly access: EndpointAccessView | undefined;
  readonly mayWrite: boolean;
}

/**
 * One endpoint, whether the account has access to it, and the control to change that.
 *
 * Its own component so each row's mutations report their own state: giving access
 * to one endpoint must not show a spinner, or a failure, on every other row.
 */
function EndpointAccessRow({
  user,
  endpoint,
  access,
  mayWrite,
}: Readonly<EndpointAccessRowProps>) {
  const { tenant } = useConsoleContext();
  const grant = useGrantEndpointAccess(tenant, user.id);
  const revoke = useRevokeEndpointAccess(tenant, user.id);
  const label = `Access to ${endpoint.name}`;

  return (
    <section
      aria-label={label}
      className="border-base-300 rounded-box flex flex-col gap-3 border p-4"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="font-medium break-words">{endpoint.name}</h3>
          <div className="text-base-content/60 flex flex-wrap items-center gap-2 text-xs max-sm:text-sm">
            <code className="font-mono">{endpoint.slug}</code>
            <span>{endpointKindLabel(endpoint.kind)}</span>
            <span>signs in with {endpoint.authMode}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {access === undefined ? (
            <StatusBadge tone="neutral">no access</StatusBadge>
          ) : (
            <span title={`Given ${formatInstant(access.grantedAt)}`}>
              <StatusBadge tone="success">access</StatusBadge>
            </span>
          )}
          {mayWrite && access === undefined ? (
            <button
              type="button"
              className="btn btn-outline btn-sm"
              disabled={grant.isPending}
              onClick={() => {
                revoke.reset();
                grant.mutate({ endpoint: endpoint.slug, body: {} });
              }}
            >
              {grant.isPending ? (
                <span className="loading loading-spinner loading-xs" />
              ) : null}
              Give access
            </button>
          ) : null}
          {mayWrite && access !== undefined ? (
            <button
              type="button"
              className="btn btn-outline btn-error btn-sm"
              disabled={revoke.isPending}
              onClick={() => {
                // A native confirm, as for every other destructive action in the
                // console: the browser's own dialogue cannot be dismissed by a
                // stray click the way a modal overlay can.
                if (
                  globalThis.confirm(
                    `Withdraw ${user.username}'s access to ${endpoint.name}? This deletes their consents and sessions on that endpoint, and their refresh tokens there stop working. Access tokens already issued run until they expire. Their access to other endpoints is not affected.`,
                  )
                ) {
                  grant.reset();
                  revoke.mutate(endpoint.slug);
                }
              }}
            >
              {revoke.isPending ? (
                <span className="loading loading-spinner loading-xs" />
              ) : null}
              Withdraw access
            </button>
          ) : null}
        </div>
      </div>

      {grant.isError ? (
        <ErrorAlert
          message={`Access could not be given: ${describeError(grant.error)}`}
        />
      ) : null}
      {grant.isSuccess ? (
        <InfoAlert>Access given to {endpoint.name}.</InfoAlert>
      ) : null}
      {revoke.isError ? (
        <ErrorAlert
          message={`Access could not be withdrawn: ${describeError(revoke.error)}`}
        />
      ) : null}
      {revoke.isSuccess ? (
        <InfoAlert>
          Access to {endpoint.name} withdrawn. Their consents and sessions there
          are gone.
        </InfoAlert>
      ) : null}

      {access !== undefined && user.isPersona && endpoint.isProduction ? (
        <InfoAlert>
          This endpoint is marked production, so this persona is not selectable
          at sign-in here.
        </InfoAlert>
      ) : null}

      {access !== undefined && access.kind === "smart" ? (
        <SmartAccessForm
          user={user}
          endpoint={endpoint}
          access={access}
          mayWrite={mayWrite}
        />
      ) : null}
    </section>
  );
}

interface SmartAccessFormProps {
  readonly user: EndUserView;
  readonly endpoint: EndpointView;
  readonly access: EndpointAccessView;
  readonly mayWrite: boolean;
}

/**
 * The `fhirUser` reference and a persona's default context, on one SMART endpoint.
 *
 * One piece of state per field, undefined until edited, so the rendered value is
 * `edited ?? current` and a save shows through as soon as the server answers. Only
 * the changed fields are sent, and nothing at all when nothing changed.
 */
function SmartAccessForm({
  user,
  endpoint,
  access,
  mayWrite,
}: Readonly<SmartAccessFormProps>) {
  const { tenant } = useConsoleContext();
  // Its own instance, so a save reports under this form rather than as "Access
  // given." beside the control above.
  const save = useGrantEndpointAccess(tenant, user.id);

  const [fhirUser, setFhirUser] = useState<string | undefined>();
  const [defaultPatient, setDefaultPatient] = useState<string | undefined>();
  const [defaultEncounter, setDefaultEncounter] = useState<
    string | undefined
  >();
  const [intent, setIntent] = useState<string | undefined>();

  const loaded = endpointAccessFormValues(access);
  const edited = {
    fhirUser: fhirUser ?? loaded.fhirUser,
    defaultPatient: defaultPatient ?? loaded.defaultPatient,
    defaultEncounter: defaultEncounter ?? loaded.defaultEncounter,
    intent: intent ?? loaded.intent,
  };
  const body = endpointAccessBody(edited, access, user.isPersona);
  const hasChanges = Object.keys(body).length > 0;
  const issues = issuesByField(save.error);

  return (
    <form
      className="flex flex-col gap-3"
      aria-label={`Identity on ${endpoint.name}`}
      onSubmit={(event) => {
        event.preventDefault();
        // The rule, not the disabled button: an empty PUT would still be a write
        // the audit trail records.
        if (hasChanges) {
          save.mutate({ endpoint: endpoint.slug, body });
        }
      }}
    >
      <TextField
        label="fhirUser reference"
        value={edited.fhirUser}
        onChange={setFhirUser}
        error={issues["fhirUserReference"]}
        hint="A relative FHIR reference such as Practitioner/123, on this endpoint's FHIR server. Released to apps granted the fhirUser scope. Clearing this removes it."
        disabled={!mayWrite}
      />
      {user.isPersona ? (
        <>
          <TextField
            label="Default patient"
            value={edited.defaultPatient}
            onChange={setDefaultPatient}
            error={issues["defaultContext.patient"] ?? issues["defaultContext"]}
            disabled={!mayWrite}
          />
          <TextField
            label="Default encounter"
            value={edited.defaultEncounter}
            onChange={setDefaultEncounter}
            error={issues["defaultContext.encounter"]}
            disabled={!mayWrite}
          />
          <TextField
            label="Intent"
            value={edited.intent}
            onChange={setIntent}
            error={issues["defaultContext.intent"]}
            hint="Seeds this persona's launch context on this endpoint when a launch does not supply one. Emptying all three clears it."
            disabled={!mayWrite}
          />
        </>
      ) : null}

      <SaveOutcome
        error={save.error}
        issues={issues}
        isSuccess={save.isSuccess}
        saved={`Saved for ${endpoint.name}.`}
      />
      {mayWrite ? (
        <SaveRow
          label="Save"
          hasChanges={hasChanges}
          pending={save.isPending}
        />
      ) : null}
    </form>
  );
}
