/**
 * The endpoint's upstream identity provider.
 *
 * Federation is configured in one form and verified with one button, and the second
 * is the reason this page is worth having. A federation that is wrong fails between
 * two servers, at the moment somebody is standing at a login page - so the page
 * lets an operator ask Signet to fetch the provider's discovery document and say
 * exactly what it found, before anybody tries to sign in.
 *
 * The redirect URI is displayed rather than edited. It is derived from the
 * endpoint's own issuer, and the operator's job is to paste it into the provider's
 * registration - which is the transcription that goes wrong, so it is copyable.
 *
 * The client secret is write-only. The form shows whether one is stored and leaves
 * the field blank; saving with it blank keeps what is there, which is what makes it
 * possible to fix a claim mapping without re-entering a credential.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { useIdpAction, useIdpCheck, useIdpConfig } from "../api/queries.js";
import { SubmitButton, TextField } from "../components/fields.js";
import {
  CheckOutcome,
  CopyableValue,
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
} from "../components/layout.js";
import { formatInstant } from "../formatting/values.js";
import { parseList, withoutBlanks } from "../forms/lists.js";

import type { IdpConfigView } from "../api/types.js";

/** The form's fields, as text. */
interface FederationForm {
  readonly issuer: string;
  readonly displayName: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes: string;
  readonly fhirUser: string;
  readonly roles: string;
  readonly displayNameClaim: string;
  readonly attributes: string;
}

/** The form as it starts, from whatever is already configured. */
function initialForm(config: IdpConfigView | null | undefined): FederationForm {
  return {
    issuer: config?.issuer ?? "",
    displayName: config?.displayName ?? "",
    clientId: config?.clientId ?? "",
    // Always blank. See the module header: a stored secret is never sent back, and
    // an empty field means "leave it alone" rather than "clear it".
    clientSecret: "",
    scopes: (config?.scopes ?? ["openid", "profile"]).join(" "),
    fhirUser: config?.claimMappings.fhirUser ?? "",
    roles: config?.claimMappings.roles ?? "",
    displayNameClaim: config?.claimMappings.displayName ?? "",
    attributes: (config?.claimMappings.attributes ?? []).join("\n"),
  };
}

/**
 * The request body for a form.
 *
 * `clientSecret` is omitted when blank rather than sent as an empty string, which
 * is the difference between keeping the stored secret and clearing it.
 */
function requestBody(form: FederationForm): Record<string, unknown> {
  const attributes = parseList(form.attributes);
  return {
    issuer: form.issuer.trim(),
    displayName:
      form.displayName.trim() === "" ? null : form.displayName.trim(),
    clientId: form.clientId.trim(),
    ...(form.clientSecret === "" ? {} : { clientSecret: form.clientSecret }),
    scopes: form.scopes.split(/\s+/).filter((scope) => scope.length > 0),
    claimMappings: {
      ...withoutBlanks({
        fhirUser: form.fhirUser,
        roles: form.roles,
        displayName: form.displayNameClaim,
      }),
      ...(attributes.length === 0 ? {} : { attributes }),
    },
  };
}

/** The federation settings page. */
export function FederationPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const config = useIdpConfig(tenant, endpointSlug);
  const act = useIdpAction(tenant, endpointSlug);
  const check = useIdpCheck(tenant, endpointSlug);
  const [form, setForm] = useState<FederationForm | undefined>();

  const mayEdit = roleAllows(role, "admin");
  const current = config.data ?? null;
  // Derived during render rather than synced by an effect: the loaded configuration
  // is the form's starting point until somebody types, and after that their edits
  // are what the form shows.
  const values = form ?? initialForm(current);
  const issues = issuesByField(act.error);

  /** Updates one field. */
  const set = (field: keyof FederationForm) => (value: string) => {
    setForm({ ...values, [field]: value });
  };

  if (config.isPending) {
    return <Loading label="Loading the identity provider" />;
  }

  return (
    <div>
      <PageHeader
        title="Identity provider"
        description="Sign end users in through an external OpenID Connect provider, and map its claims onto the identity a policy can use."
      />

      {config.error === null ? null : (
        <ErrorAlert message={describeError(config.error)} />
      )}

      {endpoint.authMode === "oidc" ? null : (
        <InfoAlert>
          This endpoint&rsquo;s sign-in mode is <code>{endpoint.authMode}</code>
          , so what is configured here is not used. Change the mode on the
          overview page to federate.
        </InfoAlert>
      )}

      <Panel
        title="Provider"
        description="The issuer is compared exactly against the provider's discovery document, so a trailing slash matters."
      >
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            act.mutate({ kind: "save", config: requestBody(values) });
          }}
        >
          <TextField
            label="Issuer"
            value={values.issuer}
            onChange={set("issuer")}
            type="url"
            placeholder="https://sso.example.org"
            hint="Signet fetches /.well-known/openid-configuration beneath this."
            error={issues["issuer"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="Display name"
            value={values.displayName}
            onChange={set("displayName")}
            placeholder="St Elsewhere SSO"
            hint="What the sign-in button says. Left blank, the page uses neutral wording rather than showing the issuer."
            error={issues["displayName"]}
            disabled={!mayEdit}
          />
          <TextField
            label="Client ID"
            value={values.clientId}
            onChange={set("clientId")}
            hint="What the provider registered Signet as."
            error={issues["clientId"]}
            disabled={!mayEdit}
            required
          />
          <TextField
            label="Client secret"
            value={values.clientSecret}
            onChange={set("clientSecret")}
            type="password"
            autoComplete="new-password"
            hint={
              current?.hasClientSecret === true
                ? "A secret is stored. Leave this blank to keep it."
                : "Leave blank if the provider registered Signet as a public client; PKCE protects the exchange either way."
            }
            error={issues["clientSecret"]}
            disabled={!mayEdit}
          />
          <TextField
            label="Scopes"
            value={values.scopes}
            onChange={set("scopes")}
            hint="Space-delimited. openid is added whether or not you list it - without it the provider returns no ID token."
            error={issues["scopes"]}
            disabled={!mayEdit}
          />

          {mayEdit ? (
            <div className="flex flex-wrap items-center gap-2">
              <SubmitButton pending={act.isPending}>Save</SubmitButton>
              {current === null ? null : (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => {
                    act.mutate({ kind: "remove" });
                    setForm(undefined);
                  }}
                >
                  Stop federating
                </button>
              )}
            </div>
          ) : null}

          {act.error === null ? null : (
            <ErrorAlert message={describeError(act.error)} />
          )}
        </form>
      </Panel>

      <Panel
        title="Claim mapping"
        description="Which of the provider's claims become the identity Signet issues tokens about. A claim not named here is not copied - an upstream provider can put anything in a token, and only what you name reaches a policy."
      >
        <div className="flex flex-col gap-3">
          <TextField
            label="FHIR user claim"
            value={values.fhirUser}
            onChange={set("fhirUser")}
            placeholder="fhirUser"
            hint="Yields a relative reference such as Practitioner/123."
            disabled={!mayEdit}
          />
          <TextField
            label="Roles claim"
            value={values.roles}
            onChange={set("roles")}
            placeholder="groups"
            hint="An array, or a space-delimited string. Both are accepted."
            disabled={!mayEdit}
          />
          <TextField
            label="Display name claim"
            value={values.displayNameClaim}
            onChange={set("displayNameClaim")}
            placeholder="name"
            disabled={!mayEdit}
          />
          <TextField
            label="Attribute claims"
            value={values.attributes}
            onChange={set("attributes")}
            placeholder="department, npi"
            hint="Copied verbatim into the user's attributes, where a policy template can read them."
            disabled={!mayEdit}
          />
          {mayEdit ? (
            <p className="text-base-content/60 text-xs max-sm:text-base">
              Saved with the provider above.
            </p>
          ) : null}
        </div>
      </Panel>

      <Panel
        title="Register this with the provider"
        description="The provider must be told to redirect back here, exactly."
      >
        {current === null ? (
          <EmptyState
            title="Nothing configured yet"
            description="Save a provider to see the redirect URI to register with it."
          />
        ) : (
          <div className="flex flex-col gap-3">
            <CopyableValue label="Redirect URI" value={current.redirectUri} />
            <p className="text-base-content/60 text-xs max-sm:text-base">
              Last checked{" "}
              {current.discoveryCachedAt === null
                ? "never"
                : formatInstant(current.discoveryCachedAt)}
              .
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
                Check the provider
              </button>
            </div>
            <CheckResult result={check.data} error={check.error} />
          </div>
        )}
      </Panel>
    </div>
  );
}

/** What the discovery check found, or why it could not look. */
function CheckResult({
  result,
  error,
}: Readonly<{
  readonly result: ReturnType<typeof useIdpCheck>["data"];
  readonly error: unknown;
}>) {
  return (
    <CheckOutcome result={result} error={error}>
      {result?.ok === true ? <Metadata result={result} /> : null}
    </CheckOutcome>
  );
}

/** What the provider's discovery document says, once it has been read. */
function Metadata({
  result,
}: Readonly<{
  readonly result: Extract<
    ReturnType<typeof useIdpCheck>["data"],
    { ok: true }
  >;
}>) {
  return (
    <div className="flex flex-col gap-2">
      <InfoAlert>
        The provider answered, and its issuer matches what is configured.
      </InfoAlert>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
        <dt className="text-base-content/60">Authorization</dt>
        <dd className="font-mono break-all">
          {result.metadata.authorizationEndpoint}
        </dd>
        <dt className="text-base-content/60">Token</dt>
        <dd className="font-mono break-all">{result.metadata.tokenEndpoint}</dd>
        <dt className="text-base-content/60">JWKS</dt>
        <dd className="font-mono break-all">{result.metadata.jwksUri}</dd>
        <dt className="text-base-content/60">Userinfo</dt>
        <dd className="font-mono break-all">
          {result.metadata.userinfoEndpoint ?? "not published"}
        </dd>
        <dt className="text-base-content/60">PKCE</dt>
        <dd>
          {result.supportsPkce
            ? "S256 supported"
            : "not advertised - Signet still sends a challenge, but this provider says it will ignore it"}
        </dd>
      </dl>
    </div>
  );
}
