/**
 * The self-serve registration queue.
 *
 * A developer asks for a client from the portal at this endpoint's `/apps` page; an
 * administrator approves or rejects it here. Approving registers the client as asked
 * and returns its secret once, if it has one.
 *
 * The payload is shown verbatim, including the scopes that were requested, because
 * the decision being made is whether *this* is what the endpoint should hand out.
 * The request is retained after the decision, so what was asked for stays visible
 * beside what was granted.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useClientRequests, useDecideClientRequest } from "../api/queries.js";
import { TextField } from "../components/fields.js";
import {
  EmptyState,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
  ShownOnce,
} from "../components/layout.js";
import { Chips, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import { clientTypeLabel, formatInstant } from "../formatting/values.js";

import type { ClientRequestView } from "../api/types.js";

/** The registration request queue. */
export function RequestsPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const requests = useClientRequests(tenant, endpointSlug);
  const decide = useDecideClientRequest(tenant, endpointSlug);
  const [note, setNote] = useState("");
  const [secret, setSecret] = useState<string | undefined>();

  const mayDecide = roleAllows(role, "admin");
  const pending = (requests.data ?? []).filter(
    (request) => request.status === "pending",
  );
  const decided = (requests.data ?? []).filter(
    (request) => request.status !== "pending",
  );

  return (
    <>
      <PageHeader
        title="Registration requests"
        description={
          <>
            Developers request a client from the portal at{" "}
            <a
              className="link font-mono text-xs"
              href={`${endpoint.issuer}/apps`}
              target="_blank"
              rel="noreferrer"
            >
              {endpoint.issuer}/apps
            </a>
            . Approving one registers it and reveals its secret once.
          </>
        }
      />

      {secret === undefined ? null : (
        <div className="mb-6">
          <ShownOnce title="Client secret" value={secret} />
        </div>
      )}

      {requests.isPending ? <Loading /> : null}
      {requests.isError ? (
        <ErrorAlert message={describeError(requests.error)} />
      ) : null}
      {decide.isError ? (
        <div className="mb-6">
          <ErrorAlert message={describeError(decide.error)} />
        </div>
      ) : null}

      {requests.data !== undefined && pending.length === 0 ? (
        <Panel>
          <EmptyState
            title="Nothing waiting"
            description="Registration requests from the developer portal appear here for approval."
          />
        </Panel>
      ) : null}

      {requests.data !== undefined && pending.length > 0 ? (
        <>
          {mayDecide ? (
            <Panel title="Decision note">
              <TextField
                label="Note"
                value={note}
                onChange={setNote}
                hint="Optional, recorded with the decision and shown in the audit trail. Useful for saying why a request was narrowed or refused."
              />
            </Panel>
          ) : null}

          {pending.map((request) => (
            <RequestCard
              key={request.id}
              request={request}
              mayDecide={mayDecide}
              pendingDecision={decide.isPending}
              onDecide={(approve) => {
                decide.mutate(
                  {
                    requestId: request.id,
                    approve,
                    ...(note.trim().length === 0
                      ? {}
                      : { decisionNote: note.trim() }),
                  },
                  {
                    onSuccess: (result) => {
                      setSecret(result.secret);
                      setNote("");
                    },
                  },
                );
              }}
            />
          ))}
        </>
      ) : null}

      {decided.length === 0 ? null : (
        <Panel
          title="Decided"
          description="Kept so that what was asked for stays visible beside what was granted."
        >
          <div className="flex flex-col gap-3">
            {decided.map((request) => (
              <div
                key={request.id}
                className="border-base-300 flex flex-wrap items-center gap-3 border-b pb-2 text-sm last:border-b-0"
              >
                <StatusBadge tone={toneForStatus(request.status)}>
                  {request.status}
                </StatusBadge>
                <span className="font-medium">{request.payload.name}</span>
                <span className="text-base-content/60 text-xs">
                  {request.requestedByEmail}
                </span>
                <span className="text-base-content/60 ml-auto text-xs">
                  {formatInstant(request.decidedAt)}
                </span>
                {request.decisionNote === null ? null : (
                  <p className="text-base-content/70 w-full text-xs max-sm:text-base">
                    {request.decisionNote}
                  </p>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}
    </>
  );
}

interface RequestCardProps {
  readonly request: ClientRequestView;
  readonly mayDecide: boolean;
  readonly pendingDecision: boolean;
  readonly onDecide: (approve: boolean) => void;
}

/** One pending request, and the two decisions available. */
function RequestCard({
  request,
  mayDecide,
  pendingDecision,
  onDecide,
}: Readonly<RequestCardProps>) {
  return (
    <Panel
      title={request.payload.name}
      description={`Requested by ${request.requestedByEmail} on ${formatInstant(request.createdAt)}`}
      actions={
        mayDecide ? (
          <>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={pendingDecision}
              onClick={() => {
                onDecide(true);
              }}
            >
              Approve
            </button>
            <button
              type="button"
              className="btn btn-outline btn-sm"
              disabled={pendingDecision}
              onClick={() => {
                onDecide(false);
              }}
            >
              Reject
            </button>
          </>
        ) : undefined
      }
    >
      <dl className="grid gap-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-base-content/70 text-xs">Authentication</dt>
          <dd>{clientTypeLabel(request.payload.clientType)}</dd>
        </div>
        <div>
          <dt className="text-base-content/70 text-xs">Contact</dt>
          <dd>{request.payload.contactEmail}</dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-base-content/70 text-xs">Redirect URIs</dt>
          <dd>
            <Chips values={request.payload.redirectUris} />
          </dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-base-content/70 text-xs">Requested scopes</dt>
          <dd>
            <Chips values={request.payload.requestedScopes} />
          </dd>
        </div>
        {request.payload.launchUri === undefined ? null : (
          <div className="sm:col-span-2">
            <dt className="text-base-content/70 text-xs">Launch URI</dt>
            <dd className="font-mono text-xs">{request.payload.launchUri}</dd>
          </div>
        )}
        {request.payload.note === undefined ? null : (
          <div className="sm:col-span-2">
            <dt className="text-base-content/70 text-xs">
              What they said it is for
            </dt>
            <dd>{request.payload.note}</dd>
          </div>
        )}
      </dl>
    </Panel>
  );
}
