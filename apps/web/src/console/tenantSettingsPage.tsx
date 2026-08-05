/**
 * Tenant membership and personal access tokens.
 *
 * Two invariants the server enforces are worth stating on the page rather than
 * leaving to an error message. A tenant can never be left without an owner, because
 * a tenant with no owner cannot grant membership to anybody and is therefore
 * permanently unadministrable. And nobody can grant a role, or mint a token, above
 * the one they hold themselves - otherwise "admin" would be a route to "owner".
 *
 * A new token's value appears once. It is stored as a SHA-256 digest, so this
 * response is the only opportunity to copy it.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useConsoleContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useApiTokens,
  useCreateApiToken,
  useMembers,
  useRemoveMember,
  useRevokeApiToken,
  useSetMemberRole,
} from "../api/queries.js";
import { SelectField, SubmitButton, TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
  ShownOnce,
} from "../components/layout.js";
import { DataTable, StatusBadge } from "../components/table.js";
import { formatInstant } from "../formatting/values.js";

import type { ApiTokenView, MemberView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** Every role, weakest first, as the selects offer them. */
const ROLE_OPTIONS: readonly {
  readonly value: string;
  readonly label: string;
}[] = [
  { value: "viewer", label: "Viewer - read only" },
  { value: "developer", label: "Developer - manage clients" },
  { value: "admin", label: "Admin - manage configuration" },
  { value: "owner", label: "Owner - manage membership" },
];

/** The tenant settings page. */
export function TenantSettingsPage() {
  const { tenant, role, session } = useConsoleContext();
  const mayAdminister = roleAllows(role, "admin");

  return (
    <>
      <PageHeader
        title="Tenant settings"
        description="Who may act on this tenant, and which scripts hold a credential for it."
      />
      <MembersPanel
        tenant={tenant}
        role={role}
        mayAdminister={mayAdminister}
        selfId={session.user?.id}
      />
      <TokensPanel tenant={tenant} role={role} mayAdminister={mayAdminister} />
    </>
  );
}

interface MembersPanelProps {
  readonly tenant: string;
  readonly role: string;
  readonly mayAdminister: boolean;
  readonly selfId: string | undefined;
}

/** The tenant's members, and how one is added or removed. */
function MembersPanel({
  tenant,
  role,
  mayAdminister,
  selfId,
}: Readonly<MembersPanelProps>) {
  const members = useMembers(tenant);
  const setRole = useSetMemberRole(tenant);
  const removeMember = useRemoveMember(tenant);

  const [email, setEmail] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const issues = issuesByField(setRole.error);

  // Nobody can grant above their own role, so the select offers only what they can.
  const grantable = ROLE_OPTIONS.filter((option) =>
    roleAllows(role, option.value),
  );

  const columns: readonly Column<MemberView>[] = [
    {
      key: "person",
      header: "Member",
      cell: (member) => (
        <div>
          <div className="font-medium">
            {member.displayName}
            {member.adminUserId === selfId ? (
              <span className="text-base-content/60 ml-2 text-xs">you</span>
            ) : null}
          </div>
          <div className="text-base-content/60 text-xs">{member.email}</div>
        </div>
      ),
    },
    {
      key: "role",
      header: "Role",
      cell: (member) => <StatusBadge>{member.role}</StatusBadge>,
    },
    {
      key: "factor",
      header: "Second factor",
      secondary: true,
      cell: (member) =>
        member.totpEnrolled ? (
          <StatusBadge tone="success">enrolled</StatusBadge>
        ) : (
          <StatusBadge tone="warning">none</StatusBadge>
        ),
    },
    {
      key: "lastLogin",
      header: "Last signed in",
      secondary: true,
      cell: (member) => (
        <span className="text-xs">{formatInstant(member.lastLoginAt)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      cell: (member) =>
        mayAdminister ? (
          <button
            type="button"
            className="btn btn-ghost btn-xs text-error"
            disabled={removeMember.isPending}
            onClick={() => {
              if (
                globalThis.confirm(
                  `Remove ${member.email} from this tenant? They lose access immediately.`,
                )
              ) {
                removeMember.mutate(member.adminUserId);
              }
            }}
          >
            Remove
          </button>
        ) : null,
    },
  ];

  return (
    <Panel
      title="Members"
      description="Membership is what grants visibility: a tenant with no membership row for someone is invisible to them, not merely read-only."
    >
      {members.isPending ? <Loading /> : null}
      {members.isError ? (
        <ErrorAlert message={describeError(members.error)} />
      ) : null}
      {removeMember.isError ? (
        <ErrorAlert message={describeError(removeMember.error)} />
      ) : null}
      {members.data === undefined ? null : (
        <DataTable
          columns={columns}
          rows={members.data}
          rowKey={(member) => member.adminUserId}
          empty={
            <EmptyState
              title="No members"
              description="This should not be possible: a tenant always keeps at least one owner."
            />
          }
        />
      )}

      {mayAdminister ? (
        <form
          className="border-base-300 flex flex-col gap-3 border-t pt-4"
          onSubmit={(event) => {
            event.preventDefault();
            setRole.mutate(
              { email: email.trim(), role: newRole },
              {
                onSuccess: () => {
                  setEmail("");
                },
              },
            );
          }}
        >
          <div className="grid items-start gap-3 sm:grid-cols-2">
            <TextField
              label="Email"
              type="email"
              value={email}
              onChange={setEmail}
              error={issues["email"]}
              hint="Must already have a console account on this deployment."
            />
            <SelectField
              label="Role"
              value={newRole}
              onChange={setNewRole}
              options={grantable}
              error={issues["role"]}
            />
          </div>
          <div>
            <SubmitButton pending={setRole.isPending}>
              Add or change
            </SubmitButton>
          </div>
          {setRole.isError && Object.keys(issues).length === 0 ? (
            <ErrorAlert message={describeError(setRole.error)} />
          ) : null}
        </form>
      ) : null}
    </Panel>
  );
}

interface TokensPanelProps {
  readonly tenant: string;
  readonly role: string;
  readonly mayAdminister: boolean;
}

/** The tenant's personal access tokens. */
function TokensPanel({
  tenant,
  role,
  mayAdminister,
}: Readonly<TokensPanelProps>) {
  const tokens = useApiTokens(tenant);
  const create = useCreateApiToken(tenant);
  const revoke = useRevokeApiToken(tenant);

  const [name, setName] = useState("");
  const [tokenRole, setTokenRole] = useState("viewer");
  const [value, setValue] = useState<string | undefined>();

  const issues = issuesByField(create.error);
  const grantable = ROLE_OPTIONS.filter((option) =>
    roleAllows(role, option.value),
  );

  const columns: readonly Column<ApiTokenView>[] = [
    {
      key: "name",
      header: "Token",
      cell: (token) => <span className="font-medium">{token.name}</span>,
    },
    {
      key: "role",
      header: "Role",
      cell: (token) => <StatusBadge>{token.role}</StatusBadge>,
    },
    {
      key: "used",
      header: "Last used",
      secondary: true,
      cell: (token) => (
        <span className="text-xs">{formatInstant(token.lastUsedAt)}</span>
      ),
    },
    {
      key: "expires",
      header: "Expires",
      secondary: true,
      cell: (token) => (
        <span className="text-xs">{formatInstant(token.expiresAt)}</span>
      ),
    },
    {
      key: "state",
      header: "State",
      cell: (token) =>
        token.revokedAt === null ? (
          <StatusBadge tone="success">live</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">revoked</StatusBadge>
        ),
    },
    {
      key: "actions",
      header: "",
      cell: (token) =>
        mayAdminister && token.revokedAt === null ? (
          <button
            type="button"
            className="btn btn-ghost btn-xs text-error"
            disabled={revoke.isPending}
            onClick={() => {
              if (
                globalThis.confirm(
                  `Revoke ${token.name}? Anything using it stops working immediately.`,
                )
              ) {
                revoke.mutate(token.id);
              }
            }}
          >
            Revoke
          </button>
        ) : null,
    },
  ];

  return (
    <Panel
      title="Personal access tokens"
      description="For scripting against the admin API. A token names this tenant and carries its own role, which may be narrower than yours."
    >
      {value === undefined ? null : (
        <ShownOnce title="Personal access token" value={value} />
      )}

      {tokens.isPending ? <Loading /> : null}
      {tokens.isError ? (
        <ErrorAlert message={describeError(tokens.error)} />
      ) : null}
      {revoke.isError ? (
        <ErrorAlert message={describeError(revoke.error)} />
      ) : null}
      {tokens.data === undefined ? null : (
        <DataTable
          columns={columns}
          rows={tokens.data}
          rowKey={(token) => token.id}
          rowClassName={(token) =>
            token.revokedAt === null ? undefined : "opacity-60"
          }
          empty={
            <EmptyState
              title="No tokens"
              description="Mint one to drive this tenant's configuration from a script or a pipeline."
            />
          }
        />
      )}

      {mayAdminister ? (
        <form
          className="border-base-300 flex flex-col gap-3 border-t pt-4"
          onSubmit={(event) => {
            event.preventDefault();
            create.mutate(
              { name: name.trim(), role: tokenRole },
              {
                onSuccess: (created) => {
                  setValue(created.value);
                  setName("");
                },
              },
            );
          }}
        >
          <div className="grid items-start gap-3 sm:grid-cols-2">
            <TextField
              label="Name"
              value={name}
              onChange={setName}
              error={issues["name"]}
              hint="What holds it. The audit trail names the token, not you."
            />
            <SelectField
              label="Role"
              value={tokenRole}
              onChange={setTokenRole}
              options={grantable}
              error={issues["role"]}
            />
          </div>
          <div>
            <SubmitButton pending={create.isPending}>Mint token</SubmitButton>
          </div>
          {create.isError && Object.keys(issues).length === 0 ? (
            <ErrorAlert message={describeError(create.error)} />
          ) : null}
        </form>
      ) : null}
    </Panel>
  );
}
