/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * One client.
 *
 * Suspending is offered before deleting, and says what it does: it revokes the
 * tokens the client already holds as well as refusing future ones, which is what an
 * operator means when they suspend an app that is misbehaving. Deleting is available
 * and warned about, because it takes the registration's history with it.
 *
 * Rotating the secret invalidates the old one immediately. There is no overlap
 * window: two live secrets would mean a leaked one stays usable for as long as the
 * rollout takes.
 *
 * Author: John Grimes
 */

import { describeVouching } from "@signet/core";
import { useState } from "react";
import { useNavigate, useParams } from "react-router";

import { endpointRoute } from "./routes.js";
import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useClient,
  useDeleteClient,
  useRotateSecret,
  useUpdateClient,
} from "../api/queries.js";
import {
  ListField,
  PatchForm,
  SaveOutcome,
  SaveRow,
  SelectField,
  TextField,
} from "../components/fields.js";
import {
  CopyableValue,
  DetailList,
  DetailRow,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
  ShownOnce,
} from "../components/layout.js";
import { Chips, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import {
  clientTypeLabel,
  countOf,
  formatInstant,
} from "../formatting/values.js";
import { clientFormValues, clientPatch } from "../forms/clientEdit.js";

import type { ClientView } from "../api/types.js";

/**
 * Whether a symmetric client has a secret, in words.
 *
 * Worth saying rather than leaving implicit: a confidential client with no secret is
 * registered and cannot authenticate, which looks from the app's side like a broken
 * deployment.
 *
 * @param hasSecret - Whether a secret is set.
 */
function secretDescription(hasSecret: boolean): string {
  return hasSecret ? " - secret set" : " - no secret set";
}

/**
 * What a trust anchor vouched for, and how long is left of it.
 *
 * Rendered only for a client an anchor created, which is what the null carries:
 * the vouching trio is written together at registration and never edited, so
 * there is no half-vouched client to describe.
 *
 * The expiry is stated as a fact rather than as a field, because it is not
 * editable and could not be: it comes from the statement, and moving it here
 * would be extending a registration the anchor vouched for a shorter time. When
 * it passes, every grant type is refused - which is why the badge says so rather
 * than leaving an operator to work out why an app stopped working.
 */
function VouchingPanel({
  vouching,
  registeredAt,
}: Readonly<{
  readonly vouching: ClientView["vouching"];
  readonly registeredAt: string;
}>) {
  if (vouching === null) {
    return null;
  }

  // The same function the issuance chokepoint refuses with, so the badge and the
  // token endpoint cannot disagree about whether this client still works.
  const state = describeVouching(new Date(vouching.expiresAt), new Date());

  return (
    <Panel
      title="Vouching"
      description="This client registered itself with a software statement signed by the endpoint's trust anchor, rather than being created here."
    >
      <div className="mb-3">
        <StatusBadge tone={state.expired ? "error" : "success"}>
          {state.expired ? "expired" : "active"}
        </StatusBadge>
      </div>
      <DetailList>
        <DetailRow label="Vouched by">
          <code className="font-mono text-xs break-all">{vouching.issuer}</code>
        </DetailRow>
        <DetailRow label="Statement identifier">
          <code className="font-mono text-xs break-all">
            {vouching.statementId}
          </code>
        </DetailRow>
        <DetailRow label="Registered">{formatInstant(registeredAt)}</DetailRow>
        <DetailRow label="Vouching expires">
          {formatInstant(vouching.expiresAt)}
          {state.expired
            ? " - every grant type is now refused for this client"
            : ` - ${countOf(state.daysRemaining, "day")} remaining`}
        </DetailRow>
      </DetailList>
    </Panel>
  );
}

/** One client's detail page. */
export function ClientDetailPage() {
  const { tenant, endpointSlug, role } = useEndpointContext();
  const { clientId } = useParams<{ clientId: string }>();
  const navigate = useNavigate();

  const client = useClient(tenant, endpointSlug, clientId ?? "");
  const update = useUpdateClient(tenant, endpointSlug, clientId ?? "");
  const rotate = useRotateSecret(tenant, endpointSlug, clientId ?? "");
  const destroy = useDeleteClient(tenant, endpointSlug);

  const [redirectUris, setRedirectUris] = useState<string | undefined>();
  const [scopes, setScopes] = useState<string | undefined>();
  const [name, setName] = useState<string | undefined>();
  const [status, setStatus] = useState<string | undefined>();

  const mayWrite = roleAllows(role, "developer");
  const mayDelete = roleAllows(role, "admin");

  if (client.isPending) {
    return <Loading />;
  }
  if (client.isError || client.data === undefined) {
    return <ErrorAlert message={describeError(client.error)} />;
  }

  const current = client.data;
  const issues = issuesByField(update.error);
  const loaded = clientFormValues(current);
  const edited = {
    name: name ?? loaded.name,
    status: status ?? loaded.status,
    redirectUris: redirectUris ?? loaded.redirectUris,
    allowedScopes: scopes ?? loaded.allowedScopes,
  };
  // Computed for the render, not only for the submit: an empty patch must not be
  // sent, and the reason it will not be has to be visible before the button is
  // pressed. The API accepts an empty patch and records a `client.updated` audit
  // event naming no fields, which is a write nobody asked for and nobody can undo.
  const patch = clientPatch(edited, current);
  const hasChanges = Object.keys(patch).length > 0;

  return (
    <>
      <PageHeader
        title={current.name}
        description={
          <code className="font-mono text-xs">{current.clientId}</code>
        }
        actions={
          <StatusBadge tone={toneForStatus(current.status)}>
            {current.status}
          </StatusBadge>
        }
      />

      {rotate.data?.secret === undefined ? null : (
        <div className="mb-6">
          <ShownOnce title="New client secret" value={rotate.data.secret} />
        </div>
      )}

      <VouchingPanel
        vouching={current.vouching}
        registeredAt={current.createdAt}
      />

      <Panel title="Registration">
        <DetailList>
          <DetailRow label="Client identifier">
            <CopyableValue value={current.clientId} label="client identifier" />
          </DetailRow>
          <DetailRow label="Authentication">
            {clientTypeLabel(current.clientType)}
            {current.clientType === "confidential-symmetric"
              ? secretDescription(current.hasSecret)
              : null}
          </DetailRow>
          {current.jwksUri === null ? null : (
            <DetailRow label="JWKS URI">
              <code className="font-mono text-xs">{current.jwksUri}</code>
            </DetailRow>
          )}
          <DetailRow label="Grants">
            <Chips values={current.grantTypes} />
          </DetailRow>
          <DetailRow label="Launch URI">
            {current.launchUri ?? (
              <span className="text-base-content/50">none</span>
            )}
          </DetailRow>
          <DetailRow label="Registered">
            {formatInstant(current.createdAt)}
          </DetailRow>
        </DetailList>
      </Panel>

      <PatchForm
        title="Edit"
        hasChanges={hasChanges}
        onSave={() => {
          update.mutate(patch);
        }}
      >
        <TextField
          label="Name"
          value={edited.name}
          onChange={setName}
          error={issues["name"]}
          disabled={!mayWrite}
        />
        <SelectField
          label="Status"
          value={edited.status}
          onChange={setStatus}
          error={issues["status"]}
          options={[
            { value: "active", label: "Active" },
            {
              value: "suspended",
              label: "Suspended - revokes its live tokens",
            },
            { value: "pending", label: "Pending - cannot obtain a token" },
            { value: "rejected", label: "Rejected" },
          ]}
          hint="Suspending revokes the access and refresh tokens this client already holds, as well as refusing new ones."
          disabled={!mayWrite}
        />
        <ListField
          label="Redirect URIs"
          value={edited.redirectUris}
          onChange={setRedirectUris}
          error={issues["redirectUris"] ?? issues["redirectUris.0"]}
          hint="One per line. Matched exactly."
          disabled={!mayWrite}
        />
        <ListField
          label="Allowed scopes"
          value={edited.allowedScopes}
          onChange={setScopes}
          error={issues["allowedScopes"]}
          rows={5}
          disabled={!mayWrite}
        />

        <SaveOutcome
          error={update.error}
          issues={issues}
          isSuccess={update.isSuccess}
          saved="Client saved."
        />

        {mayWrite ? (
          <SaveRow
            label="Save"
            hasChanges={hasChanges}
            pending={update.isPending}
          />
        ) : null}
      </PatchForm>

      {current.clientType === "confidential-symmetric" && mayWrite ? (
        <Panel
          title="Secret"
          description="Rotating invalidates the current secret immediately. The new one is shown once."
        >
          {rotate.isError ? (
            <ErrorAlert message={describeError(rotate.error)} />
          ) : null}
          <div>
            <button
              type="button"
              className="btn btn-outline btn-sm"
              disabled={rotate.isPending}
              onClick={() => {
                rotate.mutate();
              }}
            >
              Rotate secret
            </button>
          </div>
        </Panel>
      ) : null}

      {mayDelete ? (
        <Panel
          title="Delete"
          description="Removes the registration and everything hanging off it: its tokens, its consents and its codes. Suspending is reversible; this is not."
        >
          {destroy.isError ? (
            <ErrorAlert message={describeError(destroy.error)} />
          ) : null}
          <div>
            <button
              type="button"
              className="btn btn-error btn-outline btn-sm"
              disabled={destroy.isPending}
              onClick={() => {
                // A native confirm rather than a modal: this is destructive and
                // rare, and the browser's own dialogue cannot be dismissed by a
                // stray click the way a modal overlay can.
                if (
                  globalThis.confirm(
                    `Delete ${current.name}? Apps using this client will stop working immediately.`,
                  )
                ) {
                  destroy.mutate(current.clientId, {
                    onSuccess: () => {
                      void navigate(
                        endpointRoute(tenant, endpointSlug, "/clients"),
                      );
                    },
                  });
                }
              }}
            >
              Delete client
            </button>
          </div>
        </Panel>
      ) : null}
    </>
  );
}
