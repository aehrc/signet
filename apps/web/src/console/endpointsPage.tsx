/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The tenant's endpoints, and how a new one is created.
 *
 * The list is the console's landing page, because an endpoint is the unit an
 * operator thinks in: one issuer for one FHIR server or one API. Each row shows what
 * kind of endpoint it is, the audience its tokens carry, and whether it is
 * production - which is the flag that decides whether password-free personas are
 * selectable.
 *
 * Creating one takes four fields. The kind is the one that cannot be revisited: it
 * decides how every scope, policy and registration on the endpoint is read, so the
 * form asks for it explicitly rather than defaulting it. Everything else has a
 * defensible default, and the server generates the signing key and publishes a
 * starting policy in the same request, so an endpoint created here can serve a
 * discovery document immediately.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { Link } from "react-router";

import { endpointRoute } from "./routes.js";
import { roleAllows, useConsoleContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { useCreateEndpoint, useEndpoints } from "../api/queries.js";
import { FormFooter, RadioField, TextField } from "../components/fields.js";
import {
  CopyableValue,
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { DataTable, StatusBadge } from "../components/table.js";
import {
  audienceWording,
  ENDPOINT_KIND_OPTIONS,
  endpointKindLabel,
} from "../formatting/endpointKind.js";
import { toneForStatus } from "../formatting/status.js";
import { countOf } from "../formatting/values.js";

import type { EndpointView } from "../api/types.js";
import type { Column } from "../components/table.js";
import type { EndpointKind } from "@signet/core";

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
      key: "kind",
      header: "Kind",
      cell: (endpoint) => (
        <StatusBadge tone="neutral">
          {endpointKindLabel(endpoint.kind)}
        </StatusBadge>
      ),
    },
    {
      key: "audience",
      header: "Audience",
      cell: (endpoint) => (
        <span className="font-mono text-xs">{endpoint.audience}</span>
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
        description="An endpoint is one authorization server: SMART App Launch in front of a FHIR server, or OAuth / OpenID Connect for any other app or API. Its issuer is what you point your server or app at."
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
                description="Create one for your FHIR server or your API, and Signet will issue tokens for it."
              />
            }
          />
        )}
      </Panel>

      {endpoints.data !== undefined && endpoints.data.length > 0 ? (
        <Panel
          title="Issuers"
          description="Copy an issuer into your server's or app's configuration, or reverse-proxy its discovery document from your own base URL."
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

/** The four fields a new endpoint needs. */
function CreateEndpointForm({
  tenant,
  onDone,
}: Readonly<{ readonly tenant: string; readonly onDone: () => void }>) {
  const create = useCreateEndpoint(tenant);
  // Empty until chosen: the kind cannot be changed later, so it is not defaulted.
  const [kind, setKind] = useState<EndpointKind | "">("");
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [audience, setAudience] = useState("");

  const issues = issuesByField(create.error);
  // Worded for SMART until a kind is chosen, since that is what most operators
  // arrive to create.
  const wording = audienceWording(kind === "" ? "smart" : kind);

  return (
    <Panel title="New endpoint">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(
            { kind, slug, name, audience },
            { onSuccess: () => onDone() },
          );
        }}
      >
        <RadioField
          label="Kind"
          name="kind"
          value={kind}
          onChange={(value) => {
            setKind(value as EndpointKind);
          }}
          options={ENDPOINT_KIND_OPTIONS}
          error={issues["kind"]}
          hint="Fixed once the endpoint is created: it decides how every scope, policy and client registration on the endpoint is read."
          required
        />
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
          label={wording.label}
          type="url"
          value={audience}
          onChange={setAudience}
          error={issues["audience"]}
          hint={wording.hint}
          placeholder={wording.placeholder}
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
