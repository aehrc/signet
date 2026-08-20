/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The endpoint's signing keys.
 *
 * The three states are shown as three states, and the page explains why rotation is
 * two steps rather than one. A key generated here is published in the JWKS
 * immediately and signs nothing; promoting it makes it active. The gap between those
 * is what lets a relying party that caches the JWKS for a few minutes have the new
 * key before the first token needs it - collapsing the two into one button is how a
 * rotation rejects every token issued in the following five minutes.
 *
 * Retiring is separate again, and warned about: a retired key stops being published,
 * so any token it signed becomes unverifiable.
 *
 * Author: John Grimes
 */

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useEndpointKeys, useKeyAction } from "../api/queries.js";
import {
  CopyableValue,
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { DataTable, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import { formatDuration, formatInstant } from "../formatting/values.js";

import type { EndpointKeyView } from "../api/types.js";
import type { Column } from "../components/table.js";

/** The signing keys page. */
export function KeysPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const keys = useEndpointKeys(tenant, endpointSlug);
  const act = useKeyAction(tenant, endpointSlug);

  const mayRotate = roleAllows(role, "admin");
  const hasNext = keys.data?.some((key) => key.status === "next") ?? false;

  const columns: readonly Column<EndpointKeyView>[] = [
    {
      key: "kid",
      header: "Key",
      cell: (key) => (
        <div>
          <code className="font-mono text-xs">{key.kid}</code>
          <div className="text-base-content/60 text-xs">{key.algorithm}</div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (key) => (
        <StatusBadge tone={toneForStatus(key.status)}>{key.status}</StatusBadge>
      ),
    },
    {
      key: "created",
      header: "Created",
      cell: (key) => (
        <span className="text-xs">{formatInstant(key.createdAt)}</span>
      ),
    },
    {
      key: "activated",
      header: "Activated",
      cell: (key) => (
        <span className="text-xs">{formatInstant(key.activatedAt)}</span>
      ),
    },
    {
      key: "actions",
      header: "",
      cell: (key) =>
        mayRotate && key.status !== "retired" ? (
          <button
            type="button"
            className="btn btn-ghost btn-xs"
            disabled={act.isPending}
            onClick={() => {
              if (
                globalThis.confirm(
                  key.status === "active"
                    ? "Retire the active key? This endpoint cannot issue tokens until another key is activated, and tokens this key signed become unverifiable."
                    : "Retire this key? It will stop being published in the JWKS.",
                )
              ) {
                act.mutate({ kind: "retire", kid: key.kid });
              }
            }}
          >
            Retire
          </button>
        ) : null,
    },
  ];

  return (
    <>
      <PageHeader
        title="Signing keys"
        description="Each endpoint signs its own tokens, so rotating one affects nobody else. Private halves are envelope-encrypted at rest and are never returned by the API."
        actions={
          mayRotate ? (
            <>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                disabled={act.isPending}
                onClick={() => {
                  act.mutate({ kind: "generate", algorithm: "ES384" });
                }}
              >
                Generate ES384
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                disabled={act.isPending}
                onClick={() => {
                  act.mutate({ kind: "generate", algorithm: "RS384" });
                }}
              >
                Generate RS384
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                disabled={act.isPending || !hasNext}
                onClick={() => {
                  act.mutate({ kind: "promote" });
                }}
              >
                Promote next
              </button>
            </>
          ) : undefined
        }
      />

      {act.isError ? (
        <div className="mb-6">
          <ErrorAlert message={describeError(act.error)} />
        </div>
      ) : null}

      {hasNext ? (
        <div className="mb-6">
          <InfoAlert>
            A next key is published and signing nothing. Give relying parties
            long enough to have fetched the JWKS - a few minutes is usually
            plenty - then promote it. Tokens signed by the outgoing key stay
            verifiable until they expire, which for this endpoint is{" "}
            {formatDuration(endpoint.accessTokenTtl)}.
          </InfoAlert>
        </div>
      ) : null}

      <Panel>
        {keys.isPending ? <Loading /> : null}
        {keys.isError ? (
          <ErrorAlert message={describeError(keys.error)} />
        ) : null}
        {keys.data === undefined ? null : (
          <DataTable
            columns={columns}
            rows={keys.data}
            rowKey={(key) => key.kid}
            rowClassName={(key) =>
              key.status === "retired" ? "opacity-60" : undefined
            }
            empty={
              <EmptyState
                title="No keys"
                description="This endpoint cannot issue tokens without an active signing key. Generate one and promote it."
              />
            }
          />
        )}
      </Panel>

      <Panel
        title="Published key set"
        description="What a relying party fetches to verify a token from this endpoint. Active and next keys appear; retired ones do not."
      >
        <CopyableValue value={`${endpoint.issuer}/jwks`} label="JWKS URL" />
      </Panel>
    </>
  );
}
