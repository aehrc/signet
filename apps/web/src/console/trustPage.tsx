/**
 * The endpoint's trust anchor: who may vouch for a client registration here.
 *
 * The page's job is to make the default visible. Signet refuses dynamic client
 * registration on every endpoint, and this screen is the only thing that changes
 * that - so the refusing state is stated in words rather than being the absence of
 * a filled-in form, and the enabled state says exactly what it enabled.
 *
 * There is no separate switch. The rule *is* the capability: saving one turns
 * vouched registration on and removing it turns it off. A toggle beside the fields
 * would create a fourth state - a configured anchor that is not in force - that
 * neither the API nor the discovery document can represent.
 *
 * The key fetch is the second thing worth having. An anchor whose address is wrong
 * fails at the moment an app tries to register, where the app developer sees a
 * refusal and the operator sees nothing; the check button asks Signet to fetch the
 * keys through the same resolver a registration uses and report what came back.
 *
 * Permission ticket exchange gets its own section on this page, and it is not built
 * yet - the wireframe carries both, and this is deliberately the half that ships
 * with the registration endpoint.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useTrustAnchor,
  useTrustAnchorAction,
  useTrustAnchorCheck,
} from "../api/queries.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  CheckOutcome,
  CopyableValue,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { StatusBadge } from "../components/table.js";
import { formatInstant } from "../formatting/values.js";

import type { TrustAnchorView } from "../api/types.js";

/** The default number of days an endpoint will let a statement vouch for. */
const DEFAULT_VOUCHING_DAYS = "30";

/** The form's fields, as text. */
interface AnchorForm {
  readonly issuer: string;
  readonly jwksUri: string;
  readonly maxVouchingDays: string;
}

/** The form as it starts, from whatever is already configured. */
function initialForm(anchor: TrustAnchorView | null | undefined): AnchorForm {
  return {
    issuer: anchor?.issuer ?? "",
    jwksUri: anchor?.jwksUri ?? "",
    maxVouchingDays: String(anchor?.maxVouchingDays ?? DEFAULT_VOUCHING_DAYS),
  };
}

/**
 * The request body for a form.
 *
 * The vouching ceiling is sent as a number, and an unparseable one is sent as
 * `NaN` rather than being quietly dropped: the API refuses it and names the field,
 * which is the outcome an operator who typed "thirty" should get.
 */
function requestBody(form: AnchorForm): Record<string, unknown> {
  return {
    issuer: form.issuer.trim(),
    jwksUri: form.jwksUri.trim(),
    maxVouchingDays: Number(form.maxVouchingDays.trim()),
  };
}

/** The endpoint's trust and ticket settings. */
export function TrustPage() {
  const { tenant, endpointSlug, role } = useEndpointContext();
  const anchor = useTrustAnchor(tenant, endpointSlug);
  const act = useTrustAnchorAction(tenant, endpointSlug);
  const check = useTrustAnchorCheck(tenant, endpointSlug);
  const [form, setForm] = useState<AnchorForm | undefined>();

  const mayEdit = roleAllows(role, "admin");
  const current = anchor.data ?? null;
  // Derived during render rather than synced by an effect: the loaded rule is the
  // form's starting point until somebody types, and after that their edits are
  // what the form shows.
  const values = form ?? initialForm(current);
  const issues = issuesByField(act.error);

  /** Updates one field. */
  const set = (field: keyof AnchorForm) => (value: string) => {
    setForm({ ...values, [field]: value });
  };

  if (anchor.isPending) {
    return <Loading label="Loading the trust anchor" />;
  }

  return (
    <div>
      <PageHeader
        title="Trust and tickets"
        description="Who may vouch for a client registering itself on this endpoint, without an administrator approving it."
        actions={
          <StatusBadge tone={current === null ? "neutral" : "success"}>
            {current === null ? "registration refused" : "registration enabled"}
          </StatusBadge>
        }
      />

      {anchor.error === null ? null : (
        <ErrorAlert message={describeError(anchor.error)} />
      )}

      <Panel
        title="Dynamic client registration"
        description="The issuer is compared exactly against each statement's iss, so a trailing slash matters."
      >
        {current === null ? (
          <InfoAlert>
            This endpoint accepts no dynamic client registration. Its{" "}
            <code>/register</code> address answers 404 and its discovery
            documents advertise none. Naming a trust anchor below is what
            changes that, and removing it changes it back.
          </InfoAlert>
        ) : (
          <InfoAlert>
            This endpoint registers a client for any valid software statement
            signed by the anchor below, with no approval step. Statements from
            any other issuer are refused.
          </InfoAlert>
        )}

        <form
          className="mt-3 flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            act.mutate({ kind: "save", anchor: requestBody(values) });
          }}
        >
          <TextField
            label="Trust anchor issuer"
            value={values.issuer}
            onChange={set("issuer")}
            type="url"
            placeholder="https://anchor.example.org"
            hint="A statement whose iss is anything else is refused."
            error={issues["issuer"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="JWKS address"
            value={values.jwksUri}
            onChange={set("jwksUri")}
            type="url"
            placeholder="https://anchor.example.org/.well-known/jwks.json"
            hint="Fetched fresh on registration, never stored. A private or internal address is refused by the outbound guard."
            error={issues["jwksUri"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="Maximum vouching lifetime (days)"
            value={values.maxVouchingDays}
            onChange={set("maxVouchingDays")}
            hint="A statement vouching for longer than this is refused rather than shortened: a registration capped without the anchor's knowledge is not the one it vouched for."
            error={issues["maxVouchingDays"]}
            disabled={!mayEdit}
            required
          />

          {mayEdit ? (
            <div className="flex flex-wrap items-center gap-2">
              <SubmitButton pending={act.isPending}>Save</SubmitButton>
              {current === null ? null : (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  disabled={act.isPending}
                  onClick={() => {
                    act.mutate({ kind: "remove" });
                    setForm(undefined);
                  }}
                >
                  Stop accepting registrations
                </button>
              )}
            </div>
          ) : null}

          {act.error === null ? null : (
            <ErrorAlert message={describeError(act.error)} />
          )}
          {act.isSuccess ? <InfoAlert>Trust anchor saved.</InfoAlert> : null}
        </form>
      </Panel>

      {current === null ? null : (
        <Panel
          title="Anchor keys"
          description="What Signet will verify the next statement against."
        >
          <div className="flex flex-col gap-3">
            <CopyableValue
              label="Registration endpoint"
              value={current.registrationEndpoint}
            />
            <p className="text-base-content/60 text-xs">
              Rule last changed {formatInstant(current.updatedAt)}.
            </p>
            <div>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                disabled={check.isPending}
                onClick={() => {
                  check.mutate();
                }}
              >
                {check.isPending ? "Fetching keys…" : "Fetch the anchor's keys"}
              </button>
            </div>
            <KeyFetchResult result={check.data} error={check.error} />
          </div>
        </Panel>
      )}

      <Panel
        title="Permission ticket exchange"
        description="Accepting a ticket issuer's permission tickets at the token endpoint."
      >
        <InfoAlert>
          This endpoint accepts no permission tickets. Token exchange is refused
          as an unsupported grant type and its discovery documents advertise no
          ticket types.
        </InfoAlert>
      </Panel>
    </div>
  );
}

/** What the key fetch found, or why it could not look. */
function KeyFetchResult({
  result,
  error,
}: Readonly<{
  readonly result: ReturnType<typeof useTrustAnchorCheck>["data"];
  readonly error: unknown;
}>) {
  // A refusal here is an error rather than a note: the anchor being unreachable
  // refuses every registration, so nothing will register until it is fixed.
  return (
    <CheckOutcome result={result} error={error}>
      {result?.ok === true ? <PublishedKeys result={result} /> : null}
    </CheckOutcome>
  );
}

/** The keys the anchor published, once they have been fetched. */
function PublishedKeys({
  result,
}: Readonly<{
  readonly result: Extract<
    ReturnType<typeof useTrustAnchorCheck>["data"],
    { ok: true }
  >;
}>) {
  return (
    <div className="flex flex-col gap-2">
      <InfoAlert>
        The anchor answered at {formatInstant(result.fetchedAt)} with{" "}
        {result.keyIds.length} key
        {result.keyIds.length === 1 ? "" : "s"}.
      </InfoAlert>
      <ul className="text-base-content/70 flex flex-col gap-1 text-xs">
        {result.keyIds.map((kid) => (
          <li key={kid} className="font-mono break-all">
            {kid}
          </li>
        ))}
      </ul>
    </div>
  );
}
