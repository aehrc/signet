/**
 * One end user.
 *
 * The username is shown and never offered for editing: a stored consent and the
 * audit trail name the person by it, so changing it would rename them in the record
 * of what they agreed to. The password is not on the edit form either - it has its
 * own panel, because the API gives it its own route and its own audit event, and a
 * credential change that looked like a display-name change in the trail would be
 * worse than no trail at all.
 *
 * Disabling is offered before deleting, and says what each costs: a disabled account
 * stops authenticating on the next request and keeps its name attached to its audit
 * trail, while deleting takes the consents and tokens with it.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { Link, useParams } from "react-router";

import { endpointRoute } from "./routes.js";
import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useEndUser,
  useSetEndUserPassword,
  useUpdateEndUser,
} from "../api/queries.js";
import { ListField, SubmitButton, TextField } from "../components/fields.js";
import {
  DetailList,
  DetailRow,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { formatInstant } from "../formatting/values.js";
import { endUserFormValues, endUserPatch } from "../forms/endUserEdit.js";

/** One user's detail page. */
export function UserDetailPage() {
  const { tenant, endpointSlug, role } = useEndpointContext();
  const { userId } = useParams<{ userId: string }>();

  const user = useEndUser(tenant, endpointSlug, userId ?? "");
  const update = useUpdateEndUser(tenant, endpointSlug);

  // One piece of state per field, undefined until edited, so the rendered value is
  // `edited ?? current` and a save elsewhere on the page shows through immediately.
  const [displayName, setDisplayName] = useState<string | undefined>();
  const [fhirUser, setFhirUser] = useState<string | undefined>();
  const [roles, setRoles] = useState<string | undefined>();
  const [defaultPatient, setDefaultPatient] = useState<string | undefined>();
  const [defaultEncounter, setDefaultEncounter] = useState<
    string | undefined
  >();
  const [intent, setIntent] = useState<string | undefined>();
  const [patients, setPatients] = useState<string | undefined>();
  const [encounters, setEncounters] = useState<string | undefined>();

  const mayWrite = roleAllows(role, "admin");

  if (user.isPending) {
    return <Loading label="Loading the user…" />;
  }
  if (user.isError || user.data === undefined) {
    // The API's own 404 message - "No such user on this endpoint" - is what this
    // renders for an id that names nobody, rather than an empty form.
    return <ErrorAlert message={describeError(user.error)} />;
  }

  const current = user.data;
  const loaded = endUserFormValues(current);
  const issues = issuesByField(update.error);
  const edited = {
    displayName: displayName ?? loaded.displayName,
    fhirUser: fhirUser ?? loaded.fhirUser,
    roles: roles ?? loaded.roles,
    defaultPatient: defaultPatient ?? loaded.defaultPatient,
    defaultEncounter: defaultEncounter ?? loaded.defaultEncounter,
    intent: intent ?? loaded.intent,
    patients: patients ?? loaded.patients,
    encounters: encounters ?? loaded.encounters,
  };

  return (
    <>
      <div className="mb-2">
        <Link
          className="link link-hover text-sm"
          to={endpointRoute(tenant, endpointSlug, "/users")}
        >
          ← Users
        </Link>
      </div>

      <PageHeader
        title={current.displayName}
        description={
          <code className="font-mono text-xs">{current.username}</code>
        }
        actions={
          <>
            {current.isPersona ? (
              <StatusBadge tone="info">persona</StatusBadge>
            ) : (
              <StatusBadge tone="neutral">local account</StatusBadge>
            )}
            {current.disabledAt === null ? (
              <StatusBadge tone="success">enabled</StatusBadge>
            ) : (
              <StatusBadge tone="warning">disabled</StatusBadge>
            )}
          </>
        }
      />

      <Panel
        title="Summary"
        description="The username is not editable: stored consents and the audit trail name the person by it."
      >
        <DetailList>
          <DetailRow label="Username">
            <code className="font-mono text-xs">{current.username}</code>
          </DetailRow>
          <DetailRow label="Kind">
            {current.isPersona
              ? "Persona - chosen from a picker at sign-in, has no password"
              : "Local account"}
          </DetailRow>
          {current.isPersona ? null : (
            <DetailRow label="Password">
              {current.hasPassword ? (
                "Set"
              ) : (
                <span className="text-warning">Not set</span>
              )}
            </DetailRow>
          )}
          <DetailRow label="State">
            {current.disabledAt === null
              ? "Enabled"
              : `Disabled ${formatInstant(current.disabledAt)}`}
          </DetailRow>
          <DetailRow label="Created">
            {formatInstant(current.createdAt)}
          </DetailRow>
        </DetailList>
      </Panel>

      <Panel title="Edit">
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            update.mutate({
              userId: current.id,
              body: endUserPatch(edited, current),
            });
          }}
        >
          <TextField
            label="Display name"
            value={edited.displayName}
            onChange={setDisplayName}
            error={issues["displayName"]}
            disabled={!mayWrite}
          />
          <TextField
            label="fhirUser reference"
            value={edited.fhirUser}
            onChange={setFhirUser}
            error={issues["fhirUserReference"]}
            hint="A relative FHIR reference such as Practitioner/123. Released to apps granted the fhirUser scope. Clearing this removes it."
            disabled={!mayWrite}
          />
          <ListField
            label="Roles"
            value={edited.roles}
            onChange={setRoles}
            error={issues["roles"] ?? issues["roles.0"]}
            hint="One per line. A policy rule can require one of these before granting a scope."
            rows={2}
            disabled={!mayWrite}
          />

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
            hint="Seeds the launch context when a launch does not supply one. Emptying all three clears it."
            disabled={!mayWrite}
          />

          <ListField
            label="Patients"
            value={edited.patients}
            onChange={setPatients}
            error={issues["attributes"]}
            hint="One per line. Offered by the patient picker at authorisation time."
            rows={3}
            disabled={!mayWrite}
          />
          <ListField
            label="Encounters"
            value={edited.encounters}
            onChange={setEncounters}
            hint="One per line. Offered by the encounter picker at authorisation time."
            rows={3}
            disabled={!mayWrite}
          />

          {update.isError && Object.keys(issues).length === 0 ? (
            <ErrorAlert message={describeError(update.error)} />
          ) : null}
          {update.isSuccess ? <InfoAlert>User saved.</InfoAlert> : null}

          {mayWrite ? (
            <div>
              <SubmitButton pending={update.isPending}>Save</SubmitButton>
            </div>
          ) : null}
        </form>
      </Panel>

      {current.isPersona || !mayWrite ? null : (
        <SetPasswordPanel userId={current.id} />
      )}
    </>
  );
}

/**
 * The Set password form, for a local account.
 *
 * Its own component so that the password lives in its own state and is unmounted
 * with the panel: a value held in the page's state would survive navigating between
 * users. Rendered only for a local account - a persona has no password, and
 * offering the operation would only surface the API's refusal.
 */
function SetPasswordPanel({ userId }: Readonly<{ readonly userId: string }>) {
  const { tenant, endpointSlug } = useEndpointContext();
  const setPassword = useSetEndUserPassword(tenant, endpointSlug, userId);
  const [password, setPasswordValue] = useState("");

  const issues = issuesByField(setPassword.error);

  return (
    <Panel title="Set password">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          setPassword.mutate(password, {
            // Cleared on success rather than on submit, so a refusal leaves the
            // value to correct rather than making it be typed again.
            onSuccess: () => {
              setPasswordValue("");
            },
          });
        }}
      >
        <TextField
          label="New password"
          type="password"
          value={password}
          onChange={setPasswordValue}
          error={issues["password"]}
          hint="At least 8 characters. Replaces the current password immediately."
          autoComplete="new-password"
          required
        />

        {setPassword.isError && Object.keys(issues).length === 0 ? (
          <ErrorAlert message={describeError(setPassword.error)} />
        ) : null}
        {setPassword.isSuccess ? <InfoAlert>Password set.</InfoAlert> : null}

        <div>
          <SubmitButton pending={setPassword.isPending}>
            Set password
          </SubmitButton>
        </div>
      </form>
    </Panel>
  );
}
