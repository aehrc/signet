/**
 * End users and personas.
 *
 * The distinction is the whole point of the page, so it is stated rather than
 * implied: a local account has a password and signs in; a persona has none and is
 * chosen from a picker. Personas are only *selectable* on a non-production endpoint,
 * which is a property of the endpoint rather than of the persona - so the page says
 * so where it matters instead of hiding the option.
 *
 * Disabling is offered before deleting. A disabled account stops authenticating on
 * the next request and keeps its name attached to its audit trail; deleting takes
 * that away along with the consents it granted.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useCreateEndUser,
  useDeleteEndUser,
  useEndUsers,
  useUpdateEndUser,
} from "../api/queries.js";
import {
  CheckboxField,
  FormFooter,
  ListField,
  TextField,
} from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { Chips, DataTable, StatusBadge } from "../components/table.js";
import { countOf, formatInstant } from "../formatting/values.js";
import { parseList } from "../forms/lists.js";

import type { EndUserView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** The users and personas page. */
export function UsersPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const users = useEndUsers(tenant, endpointSlug);
  const update = useUpdateEndUser(tenant, endpointSlug);
  const destroy = useDeleteEndUser(tenant, endpointSlug);
  const [adding, setAdding] = useState(false);

  const mayWrite = roleAllows(role, "admin");

  const columns: readonly Column<EndUserView>[] = [
    {
      key: "user",
      header: "User",
      cell: (user) => (
        <div>
          <div className="font-medium">{user.displayName}</div>
          <div className="text-base-content/60 font-mono text-xs">
            {user.username}
          </div>
        </div>
      ),
    },
    {
      key: "kind",
      header: "Kind",
      cell: (user) =>
        user.isPersona ? (
          <StatusBadge tone="info">persona</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">local account</StatusBadge>
        ),
    },
    {
      key: "fhirUser",
      header: "fhirUser",
      secondary: true,
      cell: (user) =>
        user.fhirUser === null ? (
          <span className="text-base-content/50">none</span>
        ) : (
          <code className="font-mono text-xs">{user.fhirUser}</code>
        ),
    },
    {
      key: "roles",
      header: "Roles",
      secondary: true,
      cell: (user) => <Chips values={user.roles} />,
    },
    {
      key: "state",
      header: "State",
      cell: (user) =>
        user.disabledAt === null ? (
          <StatusBadge tone="success">enabled</StatusBadge>
        ) : (
          <span className="text-xs" title={formatInstant(user.disabledAt)}>
            <StatusBadge tone="warning">disabled</StatusBadge>
          </span>
        ),
    },
    {
      key: "actions",
      header: "",
      cell: (user) =>
        mayWrite ? (
          <div className="flex gap-1">
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              disabled={update.isPending}
              onClick={() => {
                update.mutate({
                  userId: user.id,
                  body: { disabled: user.disabledAt === null },
                });
              }}
            >
              {user.disabledAt === null ? "Disable" : "Enable"}
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-xs text-error"
              disabled={destroy.isPending}
              onClick={() => {
                if (
                  globalThis.confirm(
                    `Delete ${user.username}? Their stored consents and tokens go with them. Disabling keeps the audit trail readable.`,
                  )
                ) {
                  destroy.mutate(user.id);
                }
              }}
            >
              Delete
            </button>
          </div>
        ) : null,
    },
  ];

  return (
    <>
      <PageHeader
        title="Users"
        description="Who can authorise an app on this endpoint. A local account signs in with a password; a persona is chosen from a picker and has none."
        actions={
          mayWrite ? (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setAdding((open) => !open);
              }}
            >
              {adding ? "Cancel" : "Add user"}
            </button>
          ) : undefined
        }
      />

      {endpoint.isProduction ? (
        <div className="mb-6">
          <InfoAlert>
            This endpoint is marked production, so personas are not selectable
            at sign-in even if you create one. Turn that off under the
            endpoint&apos;s settings to run a connectathon against it.
          </InfoAlert>
        </div>
      ) : null}

      {adding ? (
        <EndUserForm
          onDone={() => {
            setAdding(false);
          }}
        />
      ) : null}

      <Panel
        description={
          users.data === undefined
            ? undefined
            : countOf(users.data.length, "user")
        }
      >
        {users.isPending ? <Loading /> : null}
        {users.isError ? (
          <ErrorAlert message={describeError(users.error)} />
        ) : null}
        {update.isError ? (
          <ErrorAlert message={describeError(update.error)} />
        ) : null}
        {destroy.isError ? (
          <ErrorAlert message={describeError(destroy.error)} />
        ) : null}
        {users.data === undefined ? null : (
          <DataTable
            columns={columns}
            rows={users.data}
            rowKey={(user) => user.id}
            rowClassName={(user) =>
              user.disabledAt === null ? undefined : "opacity-60"
            }
            empty={
              <EmptyState
                title="No users"
                description="Nobody can authorise an app on this endpoint yet. Add a local account, or seed a persona for a connectathon."
              />
            }
          />
        )}
      </Panel>
    </>
  );
}

/** The form for a local account or a persona. */
function EndUserForm({ onDone }: Readonly<{ readonly onDone: () => void }>) {
  const { tenant, endpointSlug } = useEndpointContext();
  const create = useCreateEndUser(tenant, endpointSlug);

  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [fhirUser, setFhirUser] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState("");
  const [isPersona, setIsPersona] = useState(false);
  const [patient, setPatient] = useState("");

  const issues = issuesByField(create.error);

  return (
    <Panel title="Add user">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            {
              username,
              displayName,
              isPersona,
              ...(isPersona ? {} : { password }),
              ...(fhirUser.trim().length === 0
                ? {}
                : { fhirUserReference: fhirUser.trim() }),
              ...(roles.trim().length === 0 ? {} : { roles: parseList(roles) }),
              ...(patient.trim().length === 0
                ? {}
                : { defaultContext: { patient: patient.trim() } }),
            },
            { onSuccess: () => onDone() },
          );
        }}
      >
        <CheckboxField
          label="This is a persona"
          checked={isPersona}
          onChange={setIsPersona}
          hint="A persona has no password and is chosen from a picker. Only selectable on a non-production endpoint."
        />

        <TextField
          label="Username"
          value={username}
          onChange={setUsername}
          error={issues["username"]}
          hint="How the account is identified in consents and in the audit trail. Cannot be changed afterwards."
          required
        />
        <TextField
          label="Display name"
          value={displayName}
          onChange={setDisplayName}
          error={issues["displayName"]}
          required
        />
        {isPersona ? null : (
          <TextField
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            error={issues["password"]}
            autoComplete="new-password"
            required
          />
        )}
        <TextField
          label="fhirUser reference"
          value={fhirUser}
          onChange={setFhirUser}
          error={issues["fhirUserReference"]}
          hint="A relative FHIR reference such as Practitioner/123. Released to apps granted the fhirUser scope."
        />
        <ListField
          label="Roles"
          value={roles}
          onChange={setRoles}
          error={issues["roles"]}
          hint="One per line. A policy rule can require one of these before granting a scope."
          rows={2}
        />
        {isPersona ? (
          <TextField
            label="Default patient"
            value={patient}
            onChange={setPatient}
            error={issues["defaultContext"]}
            hint="Seeds this persona's launch context, so a connectathon launch works without an EHR supplying one."
          />
        ) : null}

        <FormFooter
          error={create.error}
          issues={issues}
          pending={create.isPending}
          submitLabel="Add"
          onCancel={onDone}
        />
      </form>
    </Panel>
  );
}
