/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The tenant's end users and personas.
 *
 * An account belongs to the tenant: one username and one password across all of its
 * endpoints. It signs in only at the endpoints it has been given access to, so the
 * list says which those are, and an account with none is plainly an account that can
 * sign in nowhere yet.
 *
 * The distinction between a local account and a persona is stated rather than
 * implied: a local account has a password and signs in; a persona has none and is
 * chosen from a picker, on a non-production endpoint it has access to.
 *
 * The rows carry no buttons. A user's name links to their detail page, where the
 * edit form, the endpoint access and the account state actions live - so that
 * disabling and deleting sit next to the summary that explains what each of them
 * costs, rather than beside a row that shows a name and a badge.
 *
 * A new account has access to no endpoint, so the form takes the administrator
 * straight to its detail page to give it some. That is also where a local account
 * created without a password is sent its invitation: an invitation is refused until
 * the account can sign in somewhere with the password it would choose.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { Link, useNavigate } from "react-router";

import { EmailFields } from "./emailFields.js";
import { endUserRoute } from "./routes.js";
import { roleAllows, useConsoleContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { useCreateEndUser, useEndUsers } from "../api/queries.js";
import {
  CheckboxField,
  FormFooter,
  ListField,
  SelectField,
  TextField,
} from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { Chips, DataTable, StatusBadge } from "../components/table.js";
import { countOf, formatInstant } from "../formatting/values.js";
import { endUserCreateBody } from "../forms/endUserEdit.js";

import type { EndUserView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** The users and personas page. */
export function UsersPage() {
  const { tenant, role } = useConsoleContext();
  const users = useEndUsers(tenant);
  const [adding, setAdding] = useState(false);

  const mayWrite = roleAllows(role, "admin");

  const columns: readonly Column<EndUserView>[] = [
    {
      key: "user",
      header: "User",
      cell: (user) => (
        <div>
          <Link
            className="link link-hover font-medium"
            to={endUserRoute(tenant, user.id)}
          >
            {user.displayName}
          </Link>
          <div className="text-base-content/60 font-mono text-xs">
            {user.username}
          </div>
        </div>
      ),
    },
    {
      key: "kind",
      header: "Kind",
      cell: (user) => <AccountKind user={user} />,
    },
    {
      key: "endpoints",
      header: "Endpoints",
      cell: (user) => (
        <Chips values={user.endpoints.map((endpoint) => endpoint.name)} />
      ),
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
  ];

  return (
    <>
      <PageHeader
        title="Users"
        description="The tenant's accounts. Each one has one username and one password, and signs in only at the endpoints it has been given access to. A local account signs in with a password; a persona is chosen from a picker and has none."
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

      {adding ? (
        <EndUserForm
          onCancel={() => {
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
                description="Nobody can authorise an app on any of this tenant's endpoints yet. Add a local account, or seed a persona for a connectathon, then give it access to an endpoint."
              />
            }
          />
        )}
      </Panel>
    </>
  );
}

/** Whether an account is a persona or a local account, and whether it has a password. */
function AccountKind({ user }: Readonly<{ readonly user: EndUserView }>) {
  if (user.isPersona) {
    return <StatusBadge tone="info">persona</StatusBadge>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      <StatusBadge tone="neutral">local account</StatusBadge>
      {user.hasPassword ? null : (
        <StatusBadge tone="warning">no password</StatusBadge>
      )}
    </span>
  );
}

/**
 * The form for a local account or a persona.
 *
 * On success it navigates to the new account's detail page, where access to an
 * endpoint is given; there is nothing to close, because the page is left.
 */
function EndUserForm({
  onCancel,
}: Readonly<{ readonly onCancel: () => void }>) {
  const { tenant } = useConsoleContext();
  const create = useCreateEndUser(tenant);
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [emailVerified, setEmailVerified] = useState(false);
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState("");
  const [isPersona, setIsPersona] = useState(false);
  const [setup, setSetup] = useState<"password" | "invite">("password");

  const inviting = !isPersona && setup === "invite";
  const issues = issuesByField(create.error);

  return (
    <Panel
      title="Add user"
      description="The account is created with access to no endpoint. You are taken to its page next, to give it access."
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            endUserCreateBody({
              username,
              displayName,
              password,
              isPersona,
              invite: inviting,
              email,
              emailVerified,
              roles,
            }),
            {
              onSuccess: (user) => {
                void navigate(endUserRoute(tenant, user.id));
              },
            },
          );
        }}
      >
        <CheckboxField
          label="This is a persona"
          checked={isPersona}
          onChange={setIsPersona}
          hint="A persona has no password and is chosen from a picker. Only selectable on a non-production endpoint it has access to."
        />

        <TextField
          label="Username"
          value={username}
          onChange={setUsername}
          error={issues["username"]}
          hint="How the account is identified in consents and in the audit trail, at every endpoint. Cannot be changed afterwards."
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
          <SelectField
            label="Account setup"
            value={setup}
            onChange={(value) => {
              setSetup(value === "invite" ? "invite" : "password");
            }}
            options={[
              { value: "password", label: "Set a password now" },
              { value: "invite", label: "Invite by email" },
            ]}
            hint="An invitation is a link you send from your own mail client, and the person it is for chooses their own password. Send it from the account's page once it has access to an endpoint that signs in with a password."
          />
        )}
        {isPersona || inviting ? null : (
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
        <EmailFields
          email={email}
          emailVerified={emailVerified}
          onEmail={setEmail}
          onEmailVerified={setEmailVerified}
          issues={issues}
        />
        <ListField
          label="Roles"
          value={roles}
          onChange={setRoles}
          error={issues["roles"]}
          hint="One per line. A policy rule can require one of these before granting a scope."
          rows={2}
        />

        <FormFooter
          error={create.error}
          issues={issues}
          pending={create.isPending}
          submitLabel="Add"
          onCancel={onCancel}
        />
      </form>
    </Panel>
  );
}
