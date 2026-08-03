/**
 * The endpoint's registered clients.
 *
 * The form is shaped by what each client type can actually hold, because the API
 * refuses the combinations that cannot work: a public client with a secret, an
 * asymmetric client with no keys. Hiding the fields that do not apply means an
 * operator does not have to learn those rules from an error message.
 *
 * A generated secret appears once, in the panel above the list, and is never
 * retrievable afterwards — the server stores only its Argon2id digest.
 */

import { useState } from "react";
import { Link } from "react-router";

import { clientRoute } from "./routes.js";
import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { useClients, useCreateClient } from "../api/queries.js";
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
  ShownOnce,
} from "../components/layout.js";
import { Chips, DataTable, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import { clientTypeLabel, countOf } from "../formatting/values.js";
import { parseList, parseScopeList } from "../forms/lists.js";

import type { ClientView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** The client list, with the registration form above it. */
export function ClientsPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const clients = useClients(tenant, endpointSlug);
  const [registering, setRegistering] = useState(false);
  const [secret, setSecret] = useState<string | undefined>();

  const mayRegister = roleAllows(role, "developer");

  const columns: readonly Column<ClientView>[] = [
    {
      key: "name",
      header: "Client",
      cell: (client) => (
        <div>
          <Link
            className="link link-hover font-medium"
            to={clientRoute(tenant, endpointSlug, client.clientId)}
          >
            {client.name}
          </Link>
          <div className="text-base-content/60 font-mono text-xs">
            {client.clientId}
          </div>
        </div>
      ),
    },
    {
      key: "type",
      header: "Authentication",
      cell: (client) => (
        <div className="text-xs">
          <div>{clientTypeLabel(client.clientType)}</div>
          {client.clientType === "confidential-symmetric" &&
          !client.hasSecret ? (
            <span className="text-warning">no secret set</span>
          ) : null}
        </div>
      ),
    },
    {
      key: "grants",
      header: "Grants",
      secondary: true,
      cell: (client) => <Chips values={client.grantTypes} />,
    },
    {
      key: "status",
      header: "Status",
      cell: (client) => (
        <StatusBadge tone={toneForStatus(client.status)}>
          {client.status}
        </StatusBadge>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Clients"
        description="Apps registered against this endpoint. What a client may ask for is bounded by its allowed scopes, and narrowed further by the policy."
        actions={
          mayRegister ? (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setRegistering((open) => !open);
                setSecret(undefined);
              }}
            >
              {registering ? "Cancel" : "Register client"}
            </button>
          ) : undefined
        }
      />

      {secret === undefined ? null : (
        <div className="mb-6">
          <ShownOnce title="Client secret" value={secret} />
        </div>
      )}

      {registering ? (
        <ClientForm
          allows={{
            public: endpoint.capabilities["allowsPublicClients"] ?? false,
            symmetric:
              endpoint.capabilities["allowsConfidentialSymmetricClients"] ??
              false,
            asymmetric:
              endpoint.capabilities["allowsConfidentialAsymmetricClients"] ??
              false,
          }}
          onRegistered={(created) => {
            setSecret(created);
            setRegistering(false);
          }}
          onCancel={() => {
            setRegistering(false);
          }}
        />
      ) : null}

      <Panel
        description={
          clients.data === undefined
            ? undefined
            : countOf(clients.data.length, "client")
        }
      >
        {clients.isPending ? <Loading /> : null}
        {clients.isError ? (
          <ErrorAlert message={describeError(clients.error)} />
        ) : null}
        {clients.data === undefined ? null : (
          <DataTable
            columns={columns}
            rows={clients.data}
            rowKey={(client) => client.clientId}
            rowClassName={(client) =>
              client.status === "active" ? undefined : "opacity-60"
            }
            empty={
              <EmptyState
                title="No clients registered"
                description="Register an app here, or let developers request one from the portal at this endpoint's /apps page and approve it under Requests."
              />
            }
          />
        )}
      </Panel>
    </>
  );
}

/** Which client types this endpoint permits. */
interface AllowedTypes {
  readonly public: boolean;
  readonly symmetric: boolean;
  readonly asymmetric: boolean;
}

interface ClientFormProps {
  readonly allows: AllowedTypes;
  readonly onRegistered: (secret: string | undefined) => void;
  readonly onCancel: () => void;
}

/** The registration form. */
function ClientForm({
  allows,
  onRegistered,
  onCancel,
}: Readonly<ClientFormProps>) {
  const { tenant, endpointSlug } = useEndpointContext();
  const create = useCreateClient(tenant, endpointSlug);

  const permitted = [
    ...(allows.public
      ? [{ value: "public", label: "Public — PKCE only" }]
      : []),
    ...(allows.symmetric
      ? [{ value: "confidential-symmetric", label: "Confidential — secret" }]
      : []),
    ...(allows.asymmetric
      ? [
          {
            value: "confidential-asymmetric",
            label: "Confidential — signed assertion",
          },
        ]
      : []),
  ];

  const [name, setName] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientType, setClientType] = useState(permitted[0]?.value ?? "public");
  const [redirectUris, setRedirectUris] = useState("");
  const [launchUri, setLaunchUri] = useState("");
  const [scopes, setScopes] = useState(
    "openid\nfhirUser\nlaunch\nlaunch/patient\npatient/*.rs",
  );
  const [jwksUri, setJwksUri] = useState("");
  const [jwks, setJwks] = useState("");
  const [grantCode, setGrantCode] = useState(true);
  const [grantRefresh, setGrantRefresh] = useState(true);
  const [grantCredentials, setGrantCredentials] = useState(false);

  const issues = issuesByField(create.error);
  const isAsymmetric = clientType === "confidential-asymmetric";

  if (permitted.length === 0) {
    return (
      <Panel title="Register client">
        <ErrorAlert message="This endpoint allows no client types">
          <p className="text-sm">
            Enable at least one client type under the endpoint&apos;s
            capabilities first.
          </p>
        </ErrorAlert>
      </Panel>
    );
  }

  return (
    <Panel title="Register client">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();

          let parsedJwks: unknown;
          if (jwks.trim().length > 0) {
            try {
              parsedJwks = JSON.parse(jwks);
            } catch {
              // Left for the API to refuse, which reports the field by path and
              // keeps one description of what a JWKS must look like.
              parsedJwks = jwks;
            }
          }

          create.mutate(
            {
              name,
              clientType,
              ...(clientId.trim().length === 0
                ? {}
                : { clientId: clientId.trim() }),
              redirectUris: parseList(redirectUris),
              ...(launchUri.trim().length === 0
                ? {}
                : { launchUri: launchUri.trim() }),
              allowedScopes: parseScopeList(scopes),
              grantTypes: [
                ...(grantCode ? ["authorization_code"] : []),
                ...(grantRefresh ? ["refresh_token"] : []),
                ...(grantCredentials ? ["client_credentials"] : []),
              ],
              ...(isAsymmetric && jwksUri.trim().length > 0
                ? { jwksUri: jwksUri.trim() }
                : {}),
              ...(isAsymmetric && parsedJwks !== undefined
                ? { jwks: parsedJwks }
                : {}),
            },
            {
              onSuccess: (created) => {
                onRegistered(created.secret);
              },
            },
          );
        }}
      >
        <TextField
          label="Name"
          value={name}
          onChange={setName}
          error={issues["name"]}
          hint="Shown to end users on the consent screen."
          required
        />
        <TextField
          label="Client identifier"
          value={clientId}
          onChange={setClientId}
          error={issues["clientId"]}
          hint="Leave blank to have one generated. Supply one to adopt an identifier an app already uses."
        />
        <SelectField
          label="Authentication"
          value={clientType}
          onChange={setClientType}
          options={permitted}
          error={issues["clientType"]}
          hint="A public client holds no secret and authenticates with PKCE alone."
        />

        <ListField
          label="Redirect URIs"
          value={redirectUris}
          onChange={setRedirectUris}
          error={issues["redirectUris"] ?? issues["redirectUris.0"]}
          hint="One per line. Matched exactly at /authorize — never by prefix."
        />
        <TextField
          label="Launch URI"
          value={launchUri}
          onChange={setLaunchUri}
          error={issues["launchUri"]}
          hint="Where an EHR launch opens the app, with iss and launch appended. Needed for the launch simulator."
        />
        <ListField
          label="Allowed scopes"
          value={scopes}
          onChange={setScopes}
          error={issues["allowedScopes"]}
          hint="The ceiling on what this client may request. The policy narrows further; nothing widens it."
          rows={5}
        />

        <fieldset className="border-base-300 rounded-box border p-3">
          <legend className="px-1 text-sm font-medium">Grants</legend>
          <CheckboxField
            label="Authorization code"
            checked={grantCode}
            onChange={setGrantCode}
          />
          <CheckboxField
            label="Refresh token"
            checked={grantRefresh}
            onChange={setGrantRefresh}
            hint="Also requires the policy to grant offline_access or online_access."
          />
          <CheckboxField
            label="Client credentials"
            checked={grantCredentials}
            onChange={setGrantCredentials}
            hint="SMART Backend Services. A backend service never receives a refresh token."
          />
        </fieldset>

        {isAsymmetric ? (
          <>
            <TextField
              label="JWKS URI"
              type="url"
              value={jwksUri}
              onChange={setJwksUri}
              error={issues["jwksUri"]}
              hint="Fetched through the outbound guard, which refuses private and link-local addresses."
            />
            <TextField
              label="Inline JWKS"
              value={jwks}
              onChange={setJwks}
              error={issues["jwks"]}
              hint="A JSON key set. Use this or a JWKS URI, not both — with two key sources there is no single answer to which key verified an assertion."
            />
          </>
        ) : null}

        <FormFooter
          error={create.error}
          issues={issues}
          pending={create.isPending}
          submitLabel="Register"
          onCancel={onCancel}
        />
      </form>
    </Panel>
  );
}
