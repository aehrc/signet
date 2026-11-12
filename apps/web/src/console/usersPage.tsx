/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * End users and personas.
 *
 * The distinction is the whole point of the page, so it is stated rather than
 * implied: a local account has a password and signs in; a persona has none and is
 * chosen from a picker. Personas are only *selectable* on a non-production endpoint,
 * which is a property of the endpoint rather than of the persona - so the page says
 * so where it matters instead of hiding the option.
 *
 * The rows carry no buttons. A user's name links to their detail page, where the
 * edit form and the account state actions live - so that disabling and deleting sit
 * next to the summary that explains what each of them costs, rather than beside a
 * row that shows a name and a badge.
 *
 * A local account can be added without a password and sent an invitation instead,
 * so its holder chooses their own. The account is created first and the invitation
 * made straight after; if the second step fails the account still exists, so the
 * page says so and points to the detail page, where inviting can be tried again.
 *
 * Author: John Grimes
 */

import { invitationRefusal } from "@signet/core";
import { useState } from "react";
import { Link } from "react-router";

import { EmailFields } from "./emailFields.js";
import { InvitationDialog } from "./invitationDialog.js";
import { endUserRoute } from "./routes.js";
import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useCreateEndUser,
  useCreateInvitation,
  useEndUsers,
} from "../api/queries.js";
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
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { Chips, DataTable, StatusBadge } from "../components/table.js";
import { countOf, formatInstant } from "../formatting/values.js";
import { endUserCreateBody } from "../forms/endUserEdit.js";

import type { EndUserView, IssuedInvitationView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** What became of an invitation made by the Add user form. */
type InviteOutcome =
  | {
      readonly kind: "issued";
      readonly user: EndUserView;
      readonly invitation: IssuedInvitationView;
    }
  | {
      readonly kind: "failed";
      readonly user: EndUserView;
      readonly error: unknown;
    };

/** The users and personas page. */
export function UsersPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const users = useEndUsers(tenant, endpointSlug);
  const [adding, setAdding] = useState(false);
  const [outcome, setOutcome] = useState<InviteOutcome | undefined>();

  const mayWrite = roleAllows(role, "admin");

  const columns: readonly Column<EndUserView>[] = [
    {
      key: "user",
      header: "User",
      cell: (user) => (
        <div>
          <Link
            className="link link-hover font-medium"
            to={endUserRoute(tenant, endpointSlug, user.id)}
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
      cell: (user) =>
        user.isPersona ? (
          <StatusBadge tone="info">persona</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">local account</StatusBadge>
        ),
    },
    // The identity column each kind releases: a fhirUser reference on SMART, an
    // email address on OAuth.
    endpoint.kind === "smart"
      ? {
          key: "fhirUser",
          header: "fhirUser",
          cell: (user) =>
            user.fhirUser === null ? (
              <span className="text-base-content/50">none</span>
            ) : (
              <code className="font-mono text-xs">{user.fhirUser}</code>
            ),
        }
      : {
          key: "email",
          header: "Email",
          cell: (user) =>
            user.email === null ? (
              <span className="text-base-content/50">none</span>
            ) : (
              <span className="text-xs">
                {user.email}
                {user.emailVerified ? null : (
                  <span className="text-base-content/50"> (unverified)</span>
                )}
              </span>
            ),
        },
    {
      key: "roles",
      header: "Roles",
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
                setOutcome(undefined);
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
          onDone={(result) => {
            setAdding(false);
            setOutcome(result);
          }}
        />
      ) : null}

      {outcome?.kind === "failed" ? (
        <div className="mb-6">
          <ErrorAlert
            message={`${outcome.user.username} was added, but the invitation could not be made: ${describeError(outcome.error)}`}
          >
            <p className="text-sm max-sm:text-base">
              Try again from{" "}
              <Link
                className="link"
                to={endUserRoute(tenant, endpointSlug, outcome.user.id)}
              >
                their detail page
              </Link>
              .
            </p>
          </ErrorAlert>
        </div>
      ) : null}
      {outcome?.kind === "issued" ? (
        <InvitationDialog
          invitation={outcome.invitation}
          username={outcome.user.username}
          endpointName={endpoint.name}
          recipient={outcome.user.email}
          onClose={() => {
            setOutcome(undefined);
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
                description="Nobody can authorise an app on this endpoint yet. Add a local account, or seed a persona for a connectathon."
              />
            }
          />
        )}
      </Panel>
    </>
  );
}

/**
 * The form for a local account or a persona.
 *
 * `onDone` is called with no outcome when the form is cancelled or an account is
 * added with a password, and with the invitation's outcome when one was asked for.
 */
function EndUserForm({
  onDone,
}: Readonly<{ readonly onDone: (outcome?: InviteOutcome) => void }>) {
  const { tenant, endpointSlug, endpoint } = useEndpointContext();
  const create = useCreateEndUser(tenant, endpointSlug);
  const invite = useCreateInvitation(tenant, endpointSlug);

  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [fhirUser, setFhirUser] = useState("");
  const [email, setEmail] = useState("");
  const [emailVerified, setEmailVerified] = useState(false);
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState("");
  const [isPersona, setIsPersona] = useState(false);
  const [patient, setPatient] = useState("");
  const [setup, setSetup] = useState<"password" | "invite">("password");

  // Asked of a hypothetical enabled local account, since the account does not
  // exist yet: what is left is whether the endpoint checks local passwords at all.
  const mayInvite =
    invitationRefusal(endpoint, { isPersona: false, disabledAt: null }) ===
    undefined;
  const inviting = !isPersona && mayInvite && setup === "invite";
  const issues = issuesByField(create.error);
  const isSmart = endpoint.kind === "smart";

  return (
    <Panel title="Add user">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            endUserCreateBody(
              {
                username,
                displayName,
                password,
                isPersona,
                invite: inviting,
                fhirUser,
                email,
                emailVerified,
                roles,
                defaultPatient: patient,
              },
              endpoint.kind,
            ),
            {
              onSuccess: (user) => {
                if (!inviting) {
                  onDone();
                  return;
                }
                invite.mutate(user.id, {
                  onSuccess: (invitation) => {
                    onDone({ kind: "issued", user, invitation });
                  },
                  onError: (error) => {
                    onDone({ kind: "failed", user, error });
                  },
                });
              },
            },
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
        {isPersona || !mayInvite ? null : (
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
            hint="An invitation is a link you send from your own mail client. The person it is for chooses their own password."
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
        {isSmart ? (
          <TextField
            label="fhirUser reference"
            value={fhirUser}
            onChange={setFhirUser}
            error={issues["fhirUserReference"]}
            hint="A relative FHIR reference such as Practitioner/123. Released to apps granted the fhirUser scope."
          />
        ) : (
          <EmailFields
            email={email}
            emailVerified={emailVerified}
            onEmail={setEmail}
            onEmailVerified={setEmailVerified}
            issues={issues}
          />
        )}
        <ListField
          label="Roles"
          value={roles}
          onChange={setRoles}
          error={issues["roles"]}
          hint="One per line. A policy rule can require one of these before granting a scope."
          rows={2}
        />
        {isSmart && isPersona ? (
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
          pending={create.isPending || invite.isPending}
          submitLabel="Add"
          onCancel={() => {
            onDone();
          }}
        />
      </form>
    </Panel>
  );
}
