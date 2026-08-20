/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The endpoint's two trust rules: who may vouch, and whose tickets are honoured.
 *
 * The page's job is to make the defaults visible. Signet refuses dynamic client
 * registration and permission ticket exchange on every endpoint, and this screen
 * is the only thing that changes either - so each refusing state is stated in
 * words rather than being the absence of a filled-in form, and each enabled state
 * says exactly what it enabled.
 *
 * There is no separate switch on either rule. The rule *is* the capability:
 * saving one turns it on and removing it turns it off. A toggle beside the fields
 * would create a fourth state - a configured issuer that is not in force - that
 * neither the API nor the discovery document can represent.
 *
 * The key fetch is the second thing worth having, and both rules have one. An
 * issuer whose address is wrong fails at the moment an app tries to use it, where
 * the app developer sees a refusal and the operator sees nothing; the check button
 * asks Signet to fetch the keys through the same resolver the OAuth surfaces use
 * and report what came back.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import {
  useTicketIssuer,
  useTicketIssuerAction,
  useTicketIssuerCheck,
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

import type {
  TicketIssuerView,
  TrustAnchorCheckView,
  TrustAnchorView,
} from "../api/types.js";

/** The default number of days an endpoint will let a statement vouch for. */
const DEFAULT_VOUCHING_DAYS = "30";

/** The default ceiling on an exchanged access token, in seconds. */
const DEFAULT_TOKEN_LIFETIME_SECONDS = "300";

/** The anchor form's fields, as text. */
interface AnchorForm {
  readonly issuer: string;
  readonly jwksUri: string;
  readonly maxVouchingDays: string;
}

/** The ticket issuer form's fields, as text. */
interface TicketIssuerForm {
  readonly issuer: string;
  readonly jwksUri: string;
  readonly acceptedTicketTypes: string;
  readonly maxTokenLifetimeSecs: string;
}

/** The anchor form as it starts, from whatever is already configured. */
function initialForm(anchor: TrustAnchorView | null | undefined): AnchorForm {
  return {
    issuer: anchor?.issuer ?? "",
    jwksUri: anchor?.jwksUri ?? "",
    maxVouchingDays: String(anchor?.maxVouchingDays ?? DEFAULT_VOUCHING_DAYS),
  };
}

/** The ticket issuer form as it starts, from whatever is already configured. */
function initialTicketForm(
  rule: TicketIssuerView | null | undefined,
): TicketIssuerForm {
  return {
    issuer: rule?.issuer ?? "",
    jwksUri: rule?.jwksUri ?? "",
    acceptedTicketTypes: (rule?.acceptedTicketTypes ?? []).join(", "),
    maxTokenLifetimeSecs: String(
      rule?.maxTokenLifetimeSecs ?? DEFAULT_TOKEN_LIFETIME_SECONDS,
    ),
  };
}

/**
 * The request body for an anchor form.
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

/**
 * The request body for a ticket issuer form.
 *
 * The accepted types are typed as a list, separated by commas or spaces, because
 * there are one or two of them and a tag editor for that is more to operate than
 * to read. An empty list is sent as an empty list rather than being omitted: it
 * is a rule that accepts no ticket, which is a thing an operator may deliberately
 * want on the way to configuring one.
 */
function ticketRequestBody(form: TicketIssuerForm): Record<string, unknown> {
  return {
    issuer: form.issuer.trim(),
    jwksUri: form.jwksUri.trim(),
    acceptedTicketTypes: form.acceptedTicketTypes
      .split(/[\s,]+/u)
      .map((type) => type.trim())
      .filter((type) => type.length > 0),
    maxTokenLifetimeSecs: Number(form.maxTokenLifetimeSecs.trim()),
  };
}

/** The endpoint's trust and ticket settings. */
export function TrustPage() {
  const { tenant, endpointSlug, role } = useEndpointContext();
  const anchor = useTrustAnchor(tenant, endpointSlug);
  const ticketIssuer = useTicketIssuer(tenant, endpointSlug);
  const mayEdit = roleAllows(role, "admin");

  if (anchor.isPending || ticketIssuer.isPending) {
    return <Loading label="Loading the endpoint's trust rules" />;
  }

  const current = anchor.data ?? null;
  const ticketRule = ticketIssuer.data ?? null;

  return (
    <div>
      <PageHeader
        title="Trust and tickets"
        description="Who may vouch for a client registering itself on this endpoint, and whose permission tickets it will exchange for tokens."
        actions={
          <div className="flex flex-wrap gap-2">
            <StatusBadge tone={current === null ? "neutral" : "success"}>
              {current === null
                ? "registration refused"
                : "registration enabled"}
            </StatusBadge>
            <StatusBadge tone={ticketRule === null ? "neutral" : "success"}>
              {ticketRule === null ? "exchange refused" : "exchange enabled"}
            </StatusBadge>
          </div>
        }
      />

      {anchor.error === null ? null : (
        <ErrorAlert message={describeError(anchor.error)} />
      )}
      {ticketIssuer.error === null ? null : (
        <ErrorAlert message={describeError(ticketIssuer.error)} />
      )}

      <AnchorSection current={current} mayEdit={mayEdit} />
      <TicketIssuerSection current={ticketRule} mayEdit={mayEdit} />
    </div>
  );
}

/** The trust anchor rule, and the keys it publishes. */
function AnchorSection({
  current,
  mayEdit,
}: Readonly<{
  readonly current: TrustAnchorView | null;
  readonly mayEdit: boolean;
}>) {
  const { tenant, endpointSlug } = useEndpointContext();
  const act = useTrustAnchorAction(tenant, endpointSlug);
  const check = useTrustAnchorCheck(tenant, endpointSlug);
  const [form, setForm] = useState<AnchorForm | undefined>();

  // Derived during render rather than synced by an effect: the loaded rule is the
  // form's starting point until somebody types, and after that their edits are
  // what the form shows.
  const values = form ?? initialForm(current);
  const issues = issuesByField(act.error);

  /** Updates one field. */
  const set = (field: keyof AnchorForm) => (value: string) => {
    setForm({ ...values, [field]: value });
  };

  return (
    <>
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

          <RuleActions
            mayEdit={mayEdit}
            pending={act.isPending}
            removable={current !== null}
            removeLabel="Stop accepting registrations"
            onRemove={() => {
              act.mutate({ kind: "remove" });
              setForm(undefined);
            }}
          />
          <RuleFeedback
            error={act.error}
            saved={act.isSuccess}
            savedLabel="Trust anchor saved."
          />
        </form>
      </Panel>

      <KeysPanel
        title="Anchor keys"
        description="What Signet will verify the next statement against."
        address={
          current === null
            ? null
            : {
                label: "Registration endpoint",
                value: current.registrationEndpoint,
                updatedAt: current.updatedAt,
              }
        }
        check={check}
      />
    </>
  );
}

/** The permission ticket issuer rule, and the keys it publishes. */
function TicketIssuerSection({
  current,
  mayEdit,
}: Readonly<{
  readonly current: TicketIssuerView | null;
  readonly mayEdit: boolean;
}>) {
  const { tenant, endpointSlug } = useEndpointContext();
  const act = useTicketIssuerAction(tenant, endpointSlug);
  const check = useTicketIssuerCheck(tenant, endpointSlug);
  const [form, setForm] = useState<TicketIssuerForm | undefined>();

  const values = form ?? initialTicketForm(current);
  const issues = issuesByField(act.error);

  /** Updates one field. */
  const set = (field: keyof TicketIssuerForm) => (value: string) => {
    setForm({ ...values, [field]: value });
  };

  return (
    <>
      <Panel
        title="Permission ticket exchange"
        description="Accepting a ticket issuer's permission tickets at the token endpoint."
      >
        {current === null ? (
          <InfoAlert>
            This endpoint accepts no permission tickets. Token exchange is
            refused as an unsupported grant type and its discovery documents
            advertise no ticket types. Naming an issuer below is what changes
            that, and removing it changes it back.
          </InfoAlert>
        ) : (
          <InfoAlert>
            This endpoint exchanges a valid ticket from the issuer below for an
            access token, granting the overlap of what the app asked for, what
            the ticket permits and what this endpoint&rsquo;s policy allows.
            Tickets from any other issuer, and of any other type, are refused.
          </InfoAlert>
        )}

        <form
          className="mt-3 flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            act.mutate({ kind: "save", rule: ticketRequestBody(values) });
          }}
        >
          <TextField
            label="Ticket issuer"
            value={values.issuer}
            onChange={set("issuer")}
            type="url"
            placeholder="https://tickets.example.org"
            hint="A ticket whose iss is anything else is refused."
            error={issues["issuer"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="JWKS address"
            value={values.jwksUri}
            onChange={set("jwksUri")}
            type="url"
            placeholder="https://tickets.example.org/.well-known/jwks.json"
            hint="Fetched fresh on exchange, never stored. A private or internal address is refused by the outbound guard."
            error={issues["jwksUri"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="Accepted ticket types"
            value={values.acceptedTicketTypes}
            onChange={set("acceptedTicketTypes")}
            placeholder="patient-self-access"
            hint="Separated by commas. Advertised as smart_permission_ticket_types_supported; a ticket of any other type is refused, and naming none refuses every ticket."
            error={issues["acceptedTicketTypes"]}
            disabled={!mayEdit}
          />
          <TextField
            label="Maximum exchanged-token lifetime (seconds)"
            value={values.maxTokenLifetimeSecs}
            onChange={set("maxTokenLifetimeSecs")}
            hint="One of three ceilings: an exchanged token expires at the earliest of the ticket's remaining validity, this endpoint's own access token lifetime, and this."
            error={issues["maxTokenLifetimeSecs"]}
            disabled={!mayEdit}
            required
          />

          <RuleActions
            mayEdit={mayEdit}
            pending={act.isPending}
            removable={current !== null}
            removeLabel="Stop accepting tickets"
            onRemove={() => {
              act.mutate({ kind: "remove" });
              setForm(undefined);
            }}
          />
          <RuleFeedback
            error={act.error}
            saved={act.isSuccess}
            savedLabel="Ticket issuer saved."
          />
        </form>
      </Panel>

      <KeysPanel
        title="Ticket issuer keys"
        description="What Signet will verify the next permission ticket against."
        address={
          current === null
            ? null
            : {
                label: "Token endpoint",
                value: current.tokenEndpoint,
                updatedAt: current.updatedAt,
              }
        }
        check={check}
      />
    </>
  );
}

/** The save and remove controls a rule's form ends with. */
function RuleActions({
  mayEdit,
  pending,
  removable,
  removeLabel,
  onRemove,
}: Readonly<{
  readonly mayEdit: boolean;
  readonly pending: boolean;
  /** Whether there is a rule to remove. There is nothing to withdraw otherwise. */
  readonly removable: boolean;
  readonly removeLabel: string;
  readonly onRemove: () => void;
}>) {
  if (!mayEdit) {
    return null;
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <SubmitButton pending={pending}>Save</SubmitButton>
      {removable ? (
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          disabled={pending}
          onClick={onRemove}
        >
          {removeLabel}
        </button>
      ) : null}
    </div>
  );
}

/**
 * What a save did.
 *
 * Both outcomes, always: a write that reported nothing would leave an operator
 * unable to tell a saved rule from a form that silently did not submit.
 */
function RuleFeedback({
  error,
  saved,
  savedLabel,
}: Readonly<{
  readonly error: unknown;
  readonly saved: boolean;
  readonly savedLabel: string;
}>) {
  return (
    <>
      {error === null || error === undefined ? null : (
        <ErrorAlert message={describeError(error)} />
      )}
      {saved ? <InfoAlert>{savedLabel}</InfoAlert> : null}
    </>
  );
}

/** How a key fetch is driven and what it found. */
interface KeyFetch {
  readonly isPending: boolean;
  readonly mutate: () => void;
  readonly data: TrustAnchorCheckView | undefined;
  readonly error: unknown;
}

/**
 * The address an operator has to give the issuer, and what its keys look like.
 *
 * Shared by both rules because the question is the same one: an operator is
 * looking at a rule they have just saved and asking whether the issuer it names
 * can actually be reached. Renders nothing when there is no rule - there is no
 * issuer to ask about.
 */
function KeysPanel({
  title,
  description,
  address,
  check,
}: Readonly<{
  readonly title: string;
  readonly description: string;
  readonly address: {
    readonly label: string;
    readonly value: string;
    readonly updatedAt: string;
  } | null;
  readonly check: KeyFetch;
}>) {
  if (address === null) {
    return null;
  }
  return (
    <Panel title={title} description={description}>
      <div className="flex flex-col gap-3">
        <CopyableValue label={address.label} value={address.value} />
        <p className="text-base-content/60 text-xs max-sm:text-base">
          Rule last changed {formatInstant(address.updatedAt)}.
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
            {check.isPending ? "Fetching keys…" : "Fetch the published keys"}
          </button>
        </div>
        {/*
          A refusal here is an error rather than a note: an issuer that cannot be
          reached refuses everything it was configured for, so nothing will work
          until it is fixed.
        */}
        <CheckOutcome result={check.data} error={check.error}>
          {check.data?.ok === true ? (
            <PublishedKeys result={check.data} />
          ) : null}
        </CheckOutcome>
      </div>
    </Panel>
  );
}

/** The keys the issuer published, once they have been fetched. */
function PublishedKeys({
  result,
}: Readonly<{
  readonly result: Extract<TrustAnchorCheckView, { ok: true }>;
}>) {
  return (
    <div className="flex flex-col gap-2">
      <InfoAlert>
        The issuer answered at {formatInstant(result.fetchedAt)} with{" "}
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
