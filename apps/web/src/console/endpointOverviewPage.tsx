/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

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
import { issuesByField } from "../api/errors.js";
import { endpointPath } from "../api/paths.js";
import { useUpdateEndpoint } from "../api/queries.js";
import {
  CheckboxField,
  PatchForm,
  SaveOutcome,
  SaveRow,
  SelectField,
  TextField,
} from "../components/fields.js";
import {
  CopyableValue,
  DetailList,
  DetailRow,
  InfoAlert,
  Panel,
} from "../components/layout.js";
import { Chips } from "../components/table.js";
import { capabilityLabel, formatDuration } from "../formatting/values.js";
import {
  capabilityPatch,
  endpointSettingsFormValues,
  endpointSettingsIssues,
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
              className="btn btn-soft btn-primary btn-xs mb-1"
              href={endpointPath(
                tenant,
                endpointSlug,
                "/integrations/hapi-interceptor",
              )}
            >
              Download interceptor
            </a>
            <p className="text-base-content/60 mt-1 text-xs max-sm:text-base">
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

  // One piece of state per field, undefined until edited, so the rendered value is
  // `edited ?? loaded` - the same shape the two detail pages use. It matters here
  // because this form no longer remounts on a save: a field nobody touched follows
  // the endpoint as it refetches, rather than holding a stale value and reporting it
  // as a change somebody made.
  const [name, setName] = useState<string | undefined>();
  const [description, setDescription] = useState<string | undefined>();
  const [fhirBaseUrl, setFhirBaseUrl] = useState<string | undefined>();
  const [accessTokenTtl, setAccessTokenTtl] = useState<string | undefined>();
  const [refreshTokenTtl, setRefreshTokenTtl] = useState<string | undefined>();
  const [authMode, setAuthMode] = useState<string | undefined>();
  const [consentMode, setConsentMode] = useState<string | undefined>();
  const [isProduction, setIsProduction] = useState<boolean | undefined>();
  const [status, setStatus] = useState<string | undefined>();

  // Read through the same function the patch compares against, so the two cannot
  // disagree about what "unchanged" means.
  const loaded = endpointSettingsFormValues(endpoint);
  const edited = {
    name: name ?? loaded.name,
    description: description ?? loaded.description,
    fhirBaseUrl: fhirBaseUrl ?? loaded.fhirBaseUrl,
    accessTokenTtl: accessTokenTtl ?? loaded.accessTokenTtl,
    refreshTokenTtl: refreshTokenTtl ?? loaded.refreshTokenTtl,
    authMode: authMode ?? loaded.authMode,
    consentMode: consentMode ?? loaded.consentMode,
    isProduction: isProduction ?? loaded.isProduction,
    status: status ?? loaded.status,
  };

  // The form's own refusals take precedence over the API's, which describe the
  // request that was sent rather than what the field holds now.
  const refused = endpointSettingsIssues(edited);
  const issues = { ...issuesByField(update.error), ...refused };

  // Computed for the render, not only for the submit: an empty patch must not be
  // sent, and the reason it will not be has to be visible before the button is
  // pressed. The API accepts an empty patch and records an `endpoint.updated` audit
  // event naming no fields, which is a write nobody asked for and nobody can undo.
  const patch = endpointSettingsPatch(edited, endpoint);
  // A refused field blocks the whole save rather than only its own value. Saving
  // around it would write the other fields and drop this one without saying so.
  const blocked = Object.keys(refused).length > 0;
  const hasChanges = Object.keys(patch).length > 0 && !blocked;

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
        value={edited.name}
        onChange={setName}
        error={issues["name"]}
        disabled={disabled}
      />
      <TextField
        label="Description"
        value={edited.description}
        onChange={setDescription}
        error={issues["description"]}
        disabled={disabled}
      />
      <TextField
        label="FHIR base URL"
        type="url"
        value={edited.fhirBaseUrl}
        onChange={setFhirBaseUrl}
        error={issues["fhirBaseUrl"]}
        hint="Changing this changes the audience of every token issued from now on. Tokens already issued keep the old one."
        disabled={disabled}
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Access token lifetime (seconds)"
          value={edited.accessTokenTtl}
          onChange={setAccessTokenTtl}
          error={issues["accessTokenTtl"]}
          hint={`Currently ${formatDuration(endpoint.accessTokenTtl)}. A resource server cannot revoke an access token, so this is the window a leaked one still works in.`}
          disabled={disabled}
        />
        <TextField
          label="Refresh token lifetime (seconds)"
          value={edited.refreshTokenTtl}
          onChange={setRefreshTokenTtl}
          error={issues["refreshTokenTtl"]}
          hint={`Currently ${formatDuration(endpoint.refreshTokenTtl)}.`}
          disabled={disabled}
        />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <SelectField
          label="End-user authentication"
          value={edited.authMode}
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
          value={edited.consentMode}
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
        value={edited.status}
        onChange={setStatus}
        error={issues["status"]}
        options={[
          { value: "active", label: "Active" },
          { value: "disabled", label: "Disabled - refuse authorizations" },
        ]}
      />

      <CheckboxField
        label="This is a production endpoint"
        checked={edited.isProduction}
        onChange={setIsProduction}
        disabled={disabled}
        hint="Personas - accounts with no password - are only selectable when this is off. Leave it on unless this endpoint exists for a connectathon or a demonstration."
      />

      {edited.isProduction === endpoint.isProduction ? null : (
        <InfoAlert>
          {edited.isProduction
            ? "Turning this on stops personas being selectable. Anyone relying on one will have to sign in with a password."
            : "Turning this off makes every persona on this endpoint selectable without a password. Do not do this on an endpoint holding real data."}
        </InfoAlert>
      )}

      <SaveOutcome
        error={update.error}
        issues={issues}
        isSuccess={update.isSuccess}
        saved="Settings saved."
      />

      {disabled ? null : (
        <SaveRow
          label="Save settings"
          hasChanges={hasChanges}
          pending={update.isPending}
          disabledReason={
            blocked ? "Fix the fields marked above before saving." : undefined
          }
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
  // Only the boxes somebody has actually clicked, for the same reason the settings
  // form holds only the fields somebody has typed in: a flag nobody touched follows
  // the endpoint as it refetches instead of standing as a change it is not.
  const [toggled, setToggled] = useState<Record<string, boolean>>({});

  // Sorted by name so the order does not depend on how the server happened to
  // serialise the object.
  const names = Object.keys(endpoint.capabilities).toSorted();
  const flags = Object.fromEntries(
    names.map((name) => [
      name,
      toggled[name] ?? endpoint.capabilities[name] ?? false,
    ]),
  );

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
              setToggled((current) => ({ ...current, [name]: checked }));
            }}
          />
        ))}
      </div>

      <SaveOutcome
        error={update.error}
        issues={{}}
        isSuccess={update.isSuccess}
        saved="Capabilities saved."
      />

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
