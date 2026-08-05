/**
 * One end user.
 *
 * The username is shown and never offered for editing: a stored consent and the
 * audit trail name the person by it, so changing it would rename them in the record
 * of what they agreed to. The password is not on the edit form either - it has its
 * own panel, because the API gives it its own route and its own audit event, and a
 * credential change that looked like a display-name change in the trail would be
 * worse than no trail at all.
 *
 * Disabling is offered before deleting, and says what each costs: a disabled account
 * stops authenticating on the next request and keeps its name attached to its audit
 * trail, while deleting takes the consents and tokens with it.
 *
 * Author: John Grimes
 */

import { Link, useParams } from "react-router";

import { endpointRoute } from "./routes.js";
import { useEndpointContext } from "./useConsole.js";
import { describeError } from "../api/errors.js";
import { useEndUser } from "../api/queries.js";
import {
  DetailList,
  DetailRow,
  ErrorAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { formatInstant } from "../formatting/values.js";

/** One user's detail page. */
export function UserDetailPage() {
  const { tenant, endpointSlug } = useEndpointContext();
  const { userId } = useParams<{ userId: string }>();

  const user = useEndUser(tenant, endpointSlug, userId ?? "");

  if (user.isPending) {
    return <Loading label="Loading the user…" />;
  }
  if (user.isError || user.data === undefined) {
    // The API's own 404 message - "No such user on this endpoint" - is what this
    // renders for an id that names nobody, rather than an empty form.
    return <ErrorAlert message={describeError(user.error)} />;
  }

  const current = user.data;

  return (
    <>
      <div className="mb-2">
        <Link
          className="link link-hover text-sm"
          to={endpointRoute(tenant, endpointSlug, "/users")}
        >
          ← Users
        </Link>
      </div>

      <PageHeader
        title={current.displayName}
        description={
          <code className="font-mono text-xs">{current.username}</code>
        }
        actions={
          <>
            {current.isPersona ? (
              <StatusBadge tone="info">persona</StatusBadge>
            ) : (
              <StatusBadge tone="neutral">local account</StatusBadge>
            )}
            {current.disabledAt === null ? (
              <StatusBadge tone="success">enabled</StatusBadge>
            ) : (
              <StatusBadge tone="warning">disabled</StatusBadge>
            )}
          </>
        }
      />

      <Panel
        title="Summary"
        description="The username is not editable: stored consents and the audit trail name the person by it."
      >
        <DetailList>
          <DetailRow label="Username">
            <code className="font-mono text-xs">{current.username}</code>
          </DetailRow>
          <DetailRow label="Kind">
            {current.isPersona
              ? "Persona - chosen from a picker at sign-in, has no password"
              : "Local account"}
          </DetailRow>
          {current.isPersona ? null : (
            <DetailRow label="Password">
              {current.hasPassword ? (
                "Set"
              ) : (
                <span className="text-warning">Not set</span>
              )}
            </DetailRow>
          )}
          <DetailRow label="State">
            {current.disabledAt === null
              ? "Enabled"
              : `Disabled ${formatInstant(current.disabledAt)}`}
          </DetailRow>
          <DetailRow label="Created">
            {formatInstant(current.createdAt)}
          </DetailRow>
        </DetailList>
      </Panel>
    </>
  );
}
