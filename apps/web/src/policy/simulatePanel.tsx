/**
 * The simulator, beside the editor.
 *
 * This is what makes the policy editor trustworthy: it sends the document being edited -
 * saved or not - to the server, which runs the same composition the token endpoint uses
 * and returns the decoded claims. So what is on screen is what would be minted, not an
 * approximation of it computed in the browser.
 *
 * It simulates as a registered client and, optionally, a real end user, because a
 * simulation over an invented user would answer a question nobody asked. Scopes are
 * typed as an app would request them, including ones the policy will refuse - seeing the
 * refusals and their reasons is most of the value.
 *
 * Run explicitly rather than on every keystroke. The evaluation is pure and cheap, but
 * it is a request, and a network round trip per character typed into a claim value is
 * both wasteful and visually noisy. The button says what it will do.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { policiesDiffer } from "./document.js";
import { describeError } from "../api/errors.js";
import { useClients, useEndUsers, useSimulate } from "../api/queries.js";
import { SelectField, TextField } from "../components/fields.js";
import { ErrorAlert, Panel } from "../components/layout.js";
import { Chips, StatusBadge } from "../components/table.js";
import { formatDuration } from "../formatting/values.js";

import type { PolicyDocument } from "@signet/core";

interface SimulatePanelProps {
  readonly tenant: string;
  readonly endpointSlug: string;
  /** The document as edited. Sent verbatim, so unsaved edits are what is simulated. */
  readonly document: PolicyDocument | undefined;
}

/** The simulator panel. */
export function SimulatePanel({
  tenant,
  endpointSlug,
  document,
}: Readonly<SimulatePanelProps>) {
  const clients = useClients(tenant, endpointSlug);
  const users = useEndUsers(tenant, endpointSlug);
  const simulate = useSimulate(tenant, endpointSlug);

  const [clientId, setClientId] = useState("");
  const [endUserId, setEndUserId] = useState("");
  const [grantType, setGrantType] = useState("authorization_code");
  const [scopes, setScopes] = useState(
    "openid fhirUser launch/patient patient/*.rs",
  );
  const [patient, setPatient] = useState("pat-1");
  const [encounter, setEncounter] = useState("");
  // The document the last run evaluated, so a result can say when it is stale.
  const [simulated, setSimulated] = useState<PolicyDocument | undefined>();

  const chosenClient = clientId === "" ? clients.data?.[0]?.clientId : clientId;
  const isBackend = grantType === "client_credentials";

  // A result computed from an earlier draft reads as if it were current, which is
  // the one dishonesty a simulator must not commit.
  const stale =
    simulate.data !== undefined &&
    (document === undefined ||
      simulated === undefined ||
      policiesDiffer(simulated, document));

  return (
    <Panel
      title="Simulate"
      description="Runs the document above through the same evaluation the token endpoint uses, and shows the token it would produce."
    >
      <div className="flex flex-col gap-3">
        <SelectField
          label="As this client"
          value={chosenClient ?? ""}
          options={(clients.data ?? []).map((client) => ({
            value: client.clientId,
            label: `${client.name} (${client.clientType})`,
          }))}
          onChange={setClientId}
          hint={
            clients.data?.length === 0
              ? "Register a client on this endpoint first: a simulation needs one to evaluate against."
              : undefined
          }
        />

        <SelectField
          label="Grant"
          value={grantType}
          options={[
            { value: "authorization_code", label: "Authorization code" },
            {
              value: "client_credentials",
              label: "Client credentials (no user)",
            },
            { value: "refresh_token", label: "Refresh token" },
          ]}
          onChange={setGrantType}
        />

        {isBackend ? null : (
          <SelectField
            label="As this user"
            value={endUserId}
            options={[
              { value: "", label: "No user" },
              ...(users.data ?? []).map((user) => ({
                value: user.id,
                label: `${user.displayName} (${user.username})`,
              })),
            ]}
            onChange={setEndUserId}
          />
        )}

        <TextField
          label="Requested scopes"
          value={scopes}
          onChange={setScopes}
          hint="Space-separated, as an app would send them. Include scopes you expect to be refused: the refusals and their reasons are shown."
        />

        {isBackend ? null : (
          <div className="grid gap-3 sm:grid-cols-2">
            <TextField
              label="Patient in context"
              value={patient}
              onChange={setPatient}
            />
            <TextField
              label="Encounter in context"
              value={encounter}
              onChange={setEncounter}
            />
          </div>
        )}

        <div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={
              simulate.isPending ||
              chosenClient === undefined ||
              document === undefined
            }
            onClick={() => {
              if (chosenClient === undefined) {
                return;
              }
              setSimulated(document);
              simulate.mutate({
                clientId: chosenClient,
                requestedScopes: scopes,
                grantType,
                ...(document === undefined ? {} : { document }),
                ...(isBackend || endUserId === "" ? {} : { endUserId }),
                context: {
                  ...(isBackend || patient.trim().length === 0
                    ? {}
                    : { patient: patient.trim() }),
                  ...(isBackend || encounter.trim().length === 0
                    ? {}
                    : { encounter: encounter.trim() }),
                },
              });
            }}
          >
            Simulate
          </button>
          {document === undefined ? (
            <p className="text-warning mt-2 text-xs">
              The document has a problem, so there is nothing valid to simulate.
            </p>
          ) : null}
        </div>

        {simulate.isError ? (
          <ErrorAlert message={describeError(simulate.error)} />
        ) : null}

        {simulate.data === undefined ? null : (
          <>
            {stale ? (
              <p className="text-warning text-xs" role="status">
                The document has changed since this result. Simulate again to
                see the current draft.
              </p>
            ) : null}
            <div className={stale ? "opacity-60" : ""}>
              <SimulationResult result={simulate.data} />
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

/** What the simulation reported. */
function SimulationResult({
  result,
}: Readonly<{
  readonly result: NonNullable<ReturnType<typeof useSimulate>["data"]>;
}>) {
  return (
    <div className="border-base-300 flex flex-col gap-3 border-t pt-3">
      <div>
        <p className="mb-1 text-sm font-medium">Granted</p>
        <Chips
          values={result.scope.length === 0 ? [] : result.scope.split(" ")}
        />
      </div>

      {result.denied.length === 0 ? null : (
        <div>
          <p className="mb-1 text-sm font-medium">Refused</p>
          <ul className="flex flex-col gap-1">
            {result.denied.map((entry, index) => (
              <li key={String(index)} className="text-xs">
                <code className="font-mono">{scopeText(entry.scope)}</code> -{" "}
                {entry.reason}
                {entry.ruleId === undefined ? null : (
                  <span className="text-base-content/60">
                    {" "}
                    (by {entry.ruleId})
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.narrowed.length === 0 ? null : (
        <div>
          <p className="mb-1 text-sm font-medium">Narrowed</p>
          <ul className="flex flex-col gap-1">
            {result.narrowed.map((entry, index) => (
              <li key={String(index)} className="text-xs">
                <code className="font-mono">{scopeText(entry.requested)}</code>{" "}
                became{" "}
                <code className="font-mono">{scopeText(entry.granted)}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.rejectedScopes.length === 0 ? null : (
        <div>
          <p className="mb-1 text-sm font-medium">Not valid SMART scopes</p>
          <ul className="flex flex-col gap-1">
            {result.rejectedScopes.map((entry) => (
              <li key={entry.raw} className="text-xs">
                <code className="font-mono">{entry.raw}</code> - {entry.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <StatusBadge tone="info">
          {formatDuration(result.accessTokenTtl)}
        </StatusBadge>
        {result.wouldIssueRefreshToken ? (
          <StatusBadge tone="neutral">
            refresh token, {formatDuration(result.refreshTokenTtl)}
          </StatusBadge>
        ) : (
          <StatusBadge tone="neutral">no refresh token</StatusBadge>
        )}
        {result.simulatedVersion === null ? null : (
          <span className="text-base-content/60">
            using published version {String(result.simulatedVersion)}
          </span>
        )}
      </div>

      <ClaimsBlock title="Access token" claims={result.accessTokenClaims} />
      {result.idTokenClaims === null ? (
        <p className="text-base-content/60 text-xs">
          No ID token: that needs the openid scope granted, a signed-in user,
          and an endpoint configured for OpenID Connect.
        </p>
      ) : (
        <ClaimsBlock title="ID token" claims={result.idTokenClaims} />
      )}
      {Object.keys(result.responseParameters).length === 0 ? null : (
        <ClaimsBlock
          title="Response parameters"
          claims={result.responseParameters}
        />
      )}
    </div>
  );
}

/** One decoded payload, pretty-printed. */
function ClaimsBlock({
  title,
  claims,
}: Readonly<{
  readonly title: string;
  readonly claims: Readonly<Record<string, unknown>>;
}>) {
  return (
    <div>
      <p className="mb-1 text-sm font-medium">{title}</p>
      <pre className="bg-base-200 rounded-box overflow-x-auto p-3 font-mono text-xs">
        {JSON.stringify(claims, undefined, 2)}
      </pre>
    </div>
  );
}

/**
 * Renders a scope the evaluator returned as its string form.
 *
 * The API returns parsed scopes rather than strings, because the evaluation works on
 * parsed ones. Reassembling the text here rather than asking the server for both keeps
 * the response one representation.
 */
function scopeText(scope: unknown): string {
  if (typeof scope !== "object" || scope === null) {
    return String(scope);
  }
  const record = scope as {
    kind?: unknown;
    context?: unknown;
    resourceType?: unknown;
    permissions?: unknown;
    name?: unknown;
  };
  if (record.kind === "resource") {
    const permissions = Array.isArray(record.permissions)
      ? record.permissions.join("")
      : "";
    return `${String(record.context)}/${String(record.resourceType)}.${permissions}`;
  }
  if (typeof record.name === "string") {
    return record.name;
  }
  return JSON.stringify(scope);
}
