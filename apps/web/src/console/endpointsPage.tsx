/**
 * The tenant's endpoints, and how a new one is created.
 *
 * The list is the console's landing page, because an endpoint is the unit an
 * operator thinks in: one issuer in front of one FHIR server. Each row shows the
 * issuer, since that string is what has to be pasted into the FHIR server's
 * configuration, and whether the endpoint is production - which is the flag that
 * decides whether password-free personas are selectable.
 *
 * Creating one takes three fields. Everything else has a defensible default, and the
 * server generates the signing key and publishes a starting policy in the same
 * request, so an endpoint created here can serve a discovery document immediately.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { Link } from "react-router";

import { endpointRoute } from "./routes.js";
import { roleAllows, useConsoleContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { useCreateEndpoint, useEndpoints } from "../api/queries.js";
import { FormFooter, TextField } from "../components/fields.js";
import {
  CopyableValue,
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { DataTable, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import { countOf } from "../formatting/values.js";

import type { EndpointView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** The endpoint list. */
export function EndpointsPage() {
  const { tenant, role } = useConsoleContext();
  const endpoints = useEndpoints(tenant);
  const [creating, setCreating] = useState(false);

  const mayCreate = roleAllows(role, "admin");

  const columns: readonly Column<EndpointView>[] = [
    {
      key: "name",
      header: "Endpoint",
      cell: (endpoint) => (
        <div>
          <Link
            className="link link-hover font-medium"
            to={endpointRoute(tenant, endpoint.slug)}
          >
            {endpoint.name}
          </Link>
          <div className="text-base-content/60 font-mono text-xs">
            {endpoint.slug}
          </div>
        </div>
      ),
    },
    {
      key: "fhir",
      header: "FHIR server",
      cell: (endpoint) => (
        <span className="font-mono text-xs">{endpoint.fhirBaseUrl}</span>
      ),
    },
    {
      key: "mode",
      header: "Mode",
      cell: (endpoint) =>
        endpoint.isProduction ? (
          <StatusBadge tone="neutral">production</StatusBadge>
        ) : (
          <StatusBadge tone="info">non-production</StatusBadge>
        ),
    },
    {
      key: "status",
      header: "Status",
      cell: (endpoint) => (
        <StatusBadge tone={toneForStatus(endpoint.status)}>
          {endpoint.status}
        </StatusBadge>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Endpoints"
        description="An endpoint is one SMART authorization server in front of one FHIR base URL. Its issuer is what you point your FHIR server at."
        actions={
          mayCreate ? (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setCreating((open) => !open);
              }}
            >
              {creating ? "Cancel" : "New endpoint"}
            </button>
          ) : undefined
        }
      />

      {creating ? (
        <CreateEndpointForm
          tenant={tenant}
          onDone={() => {
            setCreating(false);
          }}
        />
      ) : null}

      <Panel
        description={
          endpoints.data === undefined
            ? undefined
            : countOf(endpoints.data.length, "endpoint")
        }
      >
        {endpoints.isPending ? <Loading /> : null}
        {endpoints.isError ? (
          <ErrorAlert message={describeError(endpoints.error)} />
        ) : null}
        {endpoints.data === undefined ? null : (
          <DataTable
            columns={columns}
            rows={endpoints.data}
            rowKey={(endpoint) => endpoint.slug}
            empty={
              <EmptyState
                title="No endpoints yet"
                description="Create one, point it at your FHIR server's base URL, and Signet will serve SMART App Launch in front of it."
              />
            }
          />
        )}
      </Panel>

      {endpoints.data !== undefined && endpoints.data.length > 0 ? (
        <Panel
          title="Issuers"
          description="Copy an issuer into your FHIR server's SMART configuration, or reverse-proxy its discovery document from your own base URL."
        >
          <div className="flex flex-col gap-3">
            {endpoints.data.map((endpoint) => (
              <div key={endpoint.slug}>
                <p className="mb-1 text-sm max-sm:text-base font-medium">
                  {endpoint.name}
                </p>
                <CopyableValue value={endpoint.issuer} label="issuer" />
              </div>
            ))}
          </div>
        </Panel>
      ) : null}
    </>
  );
}

/** The three fields a new endpoint needs. */
function CreateEndpointForm({
  tenant,
  onDone,
}: Readonly<{ readonly tenant: string; readonly onDone: () => void }>) {
  const create = useCreateEndpoint(tenant);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [fhirBaseUrl, setFhirBaseUrl] = useState("");

  const issues = issuesByField(create.error);

  return (
    <Panel title="New endpoint">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            { slug, name, fhirBaseUrl },
            { onSuccess: () => onDone() },
          );
        }}
      >
        <TextField
          label="Slug"
          value={slug}
          onChange={setSlug}
          error={issues["slug"]}
          hint="Becomes part of the issuer, and cannot be changed afterwards: every token already issued carries it."
          placeholder="pathling"
          required
        />
        <TextField
          label="Name"
          value={name}
          onChange={setName}
          error={issues["name"]}
          placeholder="Pathling production"
          required
        />
        <TextField
          label="FHIR base URL"
          type="url"
          value={fhirBaseUrl}
          onChange={setFhirBaseUrl}
          error={issues["fhirBaseUrl"]}
          hint="The server this endpoint fronts. Also the audience every access token is minted for."
          placeholder="https://fhir.example.org/fhir"
          required
        />

        <FormFooter
          error={create.error}
          issues={issues}
          pending={create.isPending}
          submitLabel="Create"
          onCancel={onDone}
        />
      </form>
    </Panel>
  );
}
