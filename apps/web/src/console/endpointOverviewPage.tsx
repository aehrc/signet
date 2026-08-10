/**
 * One endpoint's configuration.
 *
 * Three things live here, in the order an operator needs them.
 *
 * The integration details first: the issuer and the discovery URL, because getting
 * an endpoint working is a matter of pasting one of those into a FHIR server, and
 * the generated HAPI interceptor for the case where the server needs code rather
 * than configuration.
 *
 * Then the settings that change behaviour - token lifetimes, how end users
 * authenticate, whether consent is remembered, and whether this is a production
 * endpoint. That last flag is the one that decides whether password-free personas
 * can be selected, so it is stated in words rather than left as a checkbox label.
 *
 * Then the capabilities. Each is a conformance claim published in
 * `.well-known/smart-configuration`, so turning one off is a promise withdrawn -
 * which is why they are edited here rather than being buried in a settings dialog.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { roleAllows, useEndpointContext } from "./useConsole.js";
import { describeError, issuesByField } from "../api/errors.js";
import { endpointPath } from "../api/paths.js";
import { useUpdateEndpoint } from "../api/queries.js";
import {
  CheckboxField,
  PatchForm,
  SaveRow,
  SelectField,
  TextField,
} from "../components/fields.js";
import {
  CopyableValue,
  DetailList,
  DetailRow,
  ErrorAlert,
  InfoAlert,
  Panel,
} from "../components/layout.js";
import { Chips } from "../components/table.js";
import { capabilityLabel, formatDuration } from "../formatting/values.js";
import {
  capabilityPatch,
  endpointSettingsFormValues,
  endpointSettingsPatch,
} from "../forms/endpointEdit.js";

/** The endpoint's overview and settings. */
export function EndpointOverviewPage() {
  const { tenant, endpointSlug, endpoint, role } = useEndpointContext();
  const mayEdit = roleAllows(role, "admin");

  return (
    <>
      <Panel
        title="Integration"
        description="What to give your FHIR server so it trusts tokens from this endpoint."
      >
        <DetailList>
          <DetailRow label="Issuer">
            <CopyableValue value={endpoint.issuer} label="issuer" />
          </DetailRow>
          <DetailRow label="SMART configuration">
            <CopyableValue
              value={endpoint.smartConfigurationUrl}
              label="discovery URL"
            />
          </DetailRow>
          <DetailRow label="JWKS">
            <CopyableValue value={`${endpoint.issuer}/jwks`} label="JWKS URL" />
          </DetailRow>
          <DetailRow label="Expected audience">
            <code className="font-mono text-xs">{endpoint.fhirBaseUrl}</code>
          </DetailRow>
          <DetailRow label="Advertised scopes">
            <Chips values={endpoint.scopesSupported} />
          </DetailRow>
          <DetailRow label="HAPI FHIR">
            <a
              className="btn btn-outline btn-xs"
              href={endpointPath(
                tenant,
                endpointSlug,
                "/integrations/hapi-interceptor",
              )}
            >
              Download interceptor
            </a>
            <p className="text-base-content/60 mt-1 text-xs">
              HAPI reads no token by itself - its authorization interceptor is
              Java you write. This generates that file for this endpoint, so the
              two sides of the handshake cannot disagree.
            </p>
          </DetailRow>
        </DetailList>
      </Panel>

      {/*
        Not keyed on `updatedAt` any more. Remounting on every save discarded the
        mutation's own state along with the form's, so "Settings saved." was
        replaced by a freshly-mounted form the moment the endpoint refetched - and
        now that Save disables itself when nothing has changed, the operator would
        be left looking at a dead button with nothing to say why. The forms track
        the loaded endpoint through the patch instead, which is what the user detail
        page does.
      */}
      <SettingsPanel disabled={!mayEdit} />
      <CapabilitiesPanel disabled={!mayEdit} />
    </>
  );
}

/** The settings that change how the endpoint behaves. */
function SettingsPanel({ disabled }: Readonly<{ readonly disabled: boolean }>) {
  const { tenant, endpointSlug, endpoint } = useEndpointContext();
  const update = useUpdateEndpoint(tenant, endpointSlug);

  // Read through the same function the patch compares against, so the two cannot
  // disagree about what "unchanged" means.
  const loaded = endpointSettingsFormValues(endpoint);
  const [name, setName] = useState(loaded.name);
  const [description, setDescription] = useState(loaded.description);
  const [fhirBaseUrl, setFhirBaseUrl] = useState(loaded.fhirBaseUrl);
  const [accessTokenTtl, setAccessTokenTtl] = useState(loaded.accessTokenTtl);
  const [refreshTokenTtl, setRefreshTokenTtl] = useState(
    loaded.refreshTokenTtl,
  );
  const [authMode, setAuthMode] = useState(loaded.authMode);
  const [consentMode, setConsentMode] = useState(loaded.consentMode);
  const [isProduction, setIsProduction] = useState(loaded.isProduction);
  const [status, setStatus] = useState(loaded.status);

  const issues = issuesByField(update.error);

  // Computed for the render, not only for the submit: an empty patch must not be
  // sent, and the reason it will not be has to be visible before the button is
  // pressed. The API accepts an empty patch and records an `endpoint.updated` audit
  // event naming no fields, which is a write nobody asked for and nobody can undo.
  const patch = endpointSettingsPatch(
    {
      name,
      description,
      fhirBaseUrl,
      accessTokenTtl,
      refreshTokenTtl,
      authMode,
      consentMode,
      isProduction,
      status,
    },
    endpoint,
  );
  const hasChanges = Object.keys(patch).length > 0;

  return (
    <PatchForm
      title="Settings"
      description="Token lifetimes, how end users authenticate, and whether this endpoint is production."
      hasChanges={hasChanges}
      onSave={() => {
        update.mutate(patch);
      }}
    >
      <TextField
        label="Name"
        value={name}
        onChange={setName}
        error={issues["name"]}
        disabled={disabled}
      />
      <TextField
        label="Description"
        value={description}
        onChange={setDescription}
        error={issues["description"]}
        disabled={disabled}
      />
      <TextField
        label="FHIR base URL"
        type="url"
        value={fhirBaseUrl}
        onChange={setFhirBaseUrl}
        error={issues["fhirBaseUrl"]}
        hint="Changing this changes the audience of every token issued from now on. Tokens already issued keep the old one."
        disabled={disabled}
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Access token lifetime (seconds)"
          value={accessTokenTtl}
          onChange={setAccessTokenTtl}
          error={issues["accessTokenTtl"]}
          hint={`Currently ${formatDuration(endpoint.accessTokenTtl)}. A resource server cannot revoke an access token, so this is the window a leaked one still works in.`}
          disabled={disabled}
        />
        <TextField
          label="Refresh token lifetime (seconds)"
          value={refreshTokenTtl}
          onChange={setRefreshTokenTtl}
          error={issues["refreshTokenTtl"]}
          hint={`Currently ${formatDuration(endpoint.refreshTokenTtl)}.`}
          disabled={disabled}
        />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <SelectField
          label="End-user authentication"
          value={authMode}
          onChange={setAuthMode}
          error={issues["authMode"]}
          options={[
            { value: "local", label: "Local accounts" },
            { value: "persona", label: "Persona picker" },
            { value: "oidc", label: "Upstream OpenID Connect" },
          ]}
        />
        <SelectField
          label="Consent"
          value={consentMode}
          onChange={setConsentMode}
          error={issues["consentMode"]}
          options={[
            { value: "always", label: "Ask every time" },
            { value: "remember", label: "Remember the decision" },
            { value: "auto", label: "Approve without asking" },
          ]}
        />
      </div>

      <SelectField
        label="Status"
        value={status}
        onChange={setStatus}
        error={issues["status"]}
        options={[
          { value: "active", label: "Active" },
          { value: "disabled", label: "Disabled - refuse authorizations" },
        ]}
      />

      <CheckboxField
        label="This is a production endpoint"
        checked={isProduction}
        onChange={setIsProduction}
        disabled={disabled}
        hint="Personas - accounts with no password - are only selectable when this is off. Leave it on unless this endpoint exists for a connectathon or a demonstration."
      />

      {isProduction === endpoint.isProduction ? null : (
        <InfoAlert>
          {isProduction
            ? "Turning this on stops personas being selectable. Anyone relying on one will have to sign in with a password."
            : "Turning this off makes every persona on this endpoint selectable without a password. Do not do this on an endpoint holding real data."}
        </InfoAlert>
      )}

      {update.isError && Object.keys(issues).length === 0 ? (
        <ErrorAlert message={describeError(update.error)} />
      ) : null}
      {update.isSuccess ? <InfoAlert>Settings saved.</InfoAlert> : null}

      {disabled ? null : (
        <SaveRow
          label="Save settings"
          hasChanges={hasChanges}
          pending={update.isPending}
        />
      )}
    </PatchForm>
  );
}

/** The capability flags, each of which is a published conformance claim. */
function CapabilitiesPanel({
  disabled,
}: Readonly<{ readonly disabled: boolean }>) {
  const { tenant, endpointSlug, endpoint } = useEndpointContext();
  const update = useUpdateEndpoint(tenant, endpointSlug);
  const [flags, setFlags] = useState<Record<string, boolean>>({
    ...endpoint.capabilities,
  });

  // Sorted by name so the order does not depend on how the server happened to
  // serialise the object.
  const names = Object.keys(endpoint.capabilities).toSorted();

  // As in the settings form above: the patch is computed for the render so that an
  // untouched set of checkboxes cannot produce an `endpoint.updated` audit event
  // naming no capability.
  const patch = capabilityPatch(flags, endpoint.capabilities);
  const hasChanges = Object.keys(patch).length > 0;

  return (
    <PatchForm
      title="Capabilities"
      description="Each of these appears in this endpoint's discovery document. Turning one off withdraws a claim apps may already rely on."
      hasChanges={hasChanges}
      onSave={() => {
        update.mutate(patch);
      }}
    >
      <div className="grid gap-1 sm:grid-cols-2">
        {names.map((name) => (
          <CheckboxField
            key={name}
            label={capabilityLabel(name)}
            checked={flags[name] ?? false}
            disabled={disabled}
            onChange={(checked) => {
              setFlags((current) => ({ ...current, [name]: checked }));
            }}
          />
        ))}
      </div>

      {update.isError ? (
        <ErrorAlert message={describeError(update.error)} />
      ) : null}
      {update.isSuccess ? <InfoAlert>Capabilities saved.</InfoAlert> : null}

      {disabled ? null : (
        <SaveRow
          label="Save capabilities"
          hasChanges={hasChanges}
          pending={update.isPending}
        />
      )}
    </PatchForm>
  );
}
