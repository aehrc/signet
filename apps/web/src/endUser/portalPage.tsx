/**
 * The developer portal: ask for a client, and come back for it.
 *
 * Two halves, and the tracking token joins them. Submitting a request returns a token
 * once; pasting it back with the request's identifier shows the request's state and, once
 * an administrator has approved it, the client identifier and where to point the app.
 *
 * The token is kept in `sessionStorage` rather than `localStorage`. It is a credential
 * that can collect a registration, and a browser tab is the right lifetime for it -
 * long enough to survive the reload after submitting, short enough not to outlive the
 * person's visit on a shared machine. It is also shown, so a developer can keep it
 * somewhere of their own.
 *
 * The client secret is deliberately not available here. It exists in exactly one
 * response - the approval, in the console - and an endpoint that could hand it out again
 * would be a way to read a credential out of the database. The portal says so, and says
 * who to ask.
 *
 * The layout is already a single column at every width, so the mobile work here is
 * the page's own padding and the wrapping of what it displays back: a redirect URI,
 * an issuer and a discovery URL are each one long word with nothing to break at.
 * The form's controls take their mobile sizing from `../components/fields.js`.
 *
 * Author: John Grimes
 */

import { useState } from "react";
import { useParams } from "react-router";

import { readClientRequest, submitClientRequest } from "./api.js";
import { describeError, issuesByField } from "../api/errors.js";
import { CentredShell } from "../components/appShell.js";
import {
  ListField,
  SelectField,
  SubmitButton,
  TextAreaField,
  TextField,
} from "../components/fields.js";
import {
  CopyableValue,
  DetailList,
  DetailRow,
  ErrorAlert,
  InfoAlert,
  Panel,
  ShownOnce,
} from "../components/layout.js";
import { Chips, StatusBadge } from "../components/table.js";
import { toneForStatus } from "../formatting/status.js";
import { formatInstant } from "../formatting/values.js";
import { parseList, parseScopeList } from "../forms/lists.js";

import type { PortalRequestView } from "./api.js";

/** Where the tracking token is kept between the submission and the reload. */
const TOKEN_STORAGE_KEY = "signet.portal.tracking";

/** Reads the remembered request, if this tab filed one. */
function rememberedRequest(): { id: string; token: string } | undefined {
  try {
    const raw = globalThis.sessionStorage.getItem(TOKEN_STORAGE_KEY);
    if (raw === null) {
      return undefined;
    }
    const parsed = JSON.parse(raw) as { id?: unknown; token?: unknown };
    return typeof parsed.id === "string" && typeof parsed.token === "string"
      ? { id: parsed.id, token: parsed.token }
      : undefined;
  } catch {
    // Storage can be unavailable or full; the portal still works, the developer just
    // pastes the token back by hand.
    return undefined;
  }
}

/** Remembers a request for this tab. */
function rememberRequest(id: string, token: string): void {
  try {
    globalThis.sessionStorage.setItem(
      TOKEN_STORAGE_KEY,
      JSON.stringify({ id, token }),
    );
  } catch {
    // See above.
  }
}

/** The developer portal. */
export function PortalPage() {
  const { tenant, endpoint } = useParams<{
    tenant: string;
    endpoint: string;
  }>();
  const remembered = rememberedRequest();
  const [requestId, setRequestId] = useState(remembered?.id ?? "");
  const [trackingToken, setTrackingToken] = useState(remembered?.token ?? "");
  const [issuedToken, setIssuedToken] = useState<string | undefined>();

  if (tenant === undefined || endpoint === undefined) {
    return (
      <CentredShell title="Not found">
        <p className="text-base-content/70 text-sm max-sm:text-base">
          This portal belongs to a particular endpoint.
        </p>
      </CentredShell>
    );
  }

  return (
    <div className="bg-base-200 min-h-screen p-6 max-sm:p-4">
      <div className="mx-auto max-w-3xl">
        <header className="mb-6">
          <p className="text-xl font-bold">Signet</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight break-words">
            Register an app
          </h1>
          <p className="text-base-content/70 mt-1 max-w-2xl text-sm break-words max-sm:text-base">
            Ask for a client on this endpoint. An administrator reviews the
            request; once it is approved, come back here with your tracking
            token to collect the client identifier.
          </p>
        </header>

        {issuedToken === undefined ? null : (
          <div className="mb-6">
            <ShownOnce title="Tracking token" value={issuedToken} />
          </div>
        )}

        <RequestForm
          tenant={tenant}
          endpoint={endpoint}
          onSubmitted={(request, token) => {
            setRequestId(request.id);
            setTrackingToken(token);
            setIssuedToken(token);
            rememberRequest(request.id, token);
          }}
        />

        <StatusPanel
          tenant={tenant}
          endpoint={endpoint}
          requestId={requestId}
          trackingToken={trackingToken}
          onRequestId={setRequestId}
          onTrackingToken={setTrackingToken}
        />
      </div>
    </div>
  );
}

interface RequestFormProps {
  readonly tenant: string;
  readonly endpoint: string;
  readonly onSubmitted: (request: PortalRequestView, token: string) => void;
}

/** The submission form. */
function RequestForm({
  tenant,
  endpoint,
  onSubmitted,
}: Readonly<RequestFormProps>) {
  const [name, setName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [clientType, setClientType] = useState("public");
  const [redirectUris, setRedirectUris] = useState("");
  const [launchUri, setLaunchUri] = useState("");
  const [scopes, setScopes] = useState(
    "openid\nfhirUser\nlaunch/patient\npatient/*.rs",
  );
  const [note, setNote] = useState("");
  const [failure, setFailure] = useState<unknown>();
  const [pending, setPending] = useState(false);

  const issues = issuesByField(failure);

  return (
    <Panel title="Your app">
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          setPending(true);
          setFailure(undefined);
          submitClientRequest(tenant, endpoint, {
            name,
            contactEmail,
            clientType,
            redirectUris: parseList(redirectUris),
            requestedScopes: parseScopeList(scopes),
            ...(launchUri.trim().length === 0
              ? {}
              : { launchUri: launchUri.trim() }),
            ...(note.trim().length === 0 ? {} : { note: note.trim() }),
          })
            .then((result) => {
              onSubmitted(result.request, result.trackingToken);
            })
            .catch((error: unknown) => {
              setFailure(error);
            })
            .finally(() => {
              setPending(false);
            });
        }}
      >
        <TextField
          label="App name"
          value={name}
          onChange={setName}
          error={issues["name"]}
          hint="Shown to users on the consent screen, so name it as they would recognise it."
          required
        />
        <TextField
          label="Contact email"
          type="email"
          value={contactEmail}
          onChange={setContactEmail}
          error={issues["contactEmail"]}
          hint="Where the administrator reaches you about this request."
          required
        />
        <SelectField
          label="How your app authenticates"
          value={clientType}
          onChange={setClientType}
          error={issues["clientType"]}
          options={[
            {
              value: "public",
              label: "Public - a browser or mobile app, PKCE only",
            },
            {
              value: "confidential-symmetric",
              label: "Confidential - a server with a shared secret",
            },
            {
              value: "confidential-asymmetric",
              label: "Confidential - a server signing its own assertions",
            },
          ]}
          hint="A public client cannot keep a secret, so it does not get one."
        />
        <ListField
          label="Redirect URIs"
          value={redirectUris}
          onChange={setRedirectUris}
          error={issues["redirectUris"] ?? issues["redirectUris.0"]}
          hint="One per line. Matched exactly, so list every one your app uses."
        />
        <TextField
          label="Launch URI"
          value={launchUri}
          onChange={setLaunchUri}
          error={issues["launchUri"]}
          hint="Where an EHR should open your app. Leave blank if it is only launched standalone."
        />
        <ListField
          label="Scopes you need"
          value={scopes}
          onChange={setScopes}
          error={issues["requestedScopes"]}
          rows={5}
          hint="Ask for the least you need: an administrator may narrow the list before approving, and a narrower request is approved faster."
        />
        <TextAreaField
          label="What your app does"
          value={note}
          onChange={setNote}
          error={issues["note"]}
          hint="Read by whoever decides. Say what the app is for and why it needs what it is asking for."
        />

        {failure !== undefined && Object.keys(issues).length === 0 ? (
          <ErrorAlert message={describeError(failure)} />
        ) : null}

        <div>
          <SubmitButton pending={pending}>Submit request</SubmitButton>
        </div>
      </form>
    </Panel>
  );
}

interface StatusPanelProps {
  readonly tenant: string;
  readonly endpoint: string;
  readonly requestId: string;
  readonly trackingToken: string;
  readonly onRequestId: (value: string) => void;
  readonly onTrackingToken: (value: string) => void;
}

/** Checking a request's state, and collecting the result. */
function StatusPanel({
  tenant,
  endpoint,
  requestId,
  trackingToken,
  onRequestId,
  onTrackingToken,
}: Readonly<StatusPanelProps>) {
  const [result, setResult] = useState<
    | {
        readonly request: PortalRequestView;
        readonly clientId?: string;
        readonly issuer?: string;
        readonly wellKnown?: string;
      }
    | undefined
  >();
  const [failure, setFailure] = useState<unknown>();
  const [pending, setPending] = useState(false);

  return (
    <Panel
      title="Check a request"
      description="Paste the identifier and tracking token you were given when you submitted."
    >
      <form
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          setPending(true);
          setFailure(undefined);
          readClientRequest(tenant, endpoint, requestId, trackingToken)
            .then((loaded) => {
              setResult(loaded);
            })
            .catch((error: unknown) => {
              setFailure(error);
              setResult(undefined);
            })
            .finally(() => {
              setPending(false);
            });
        }}
      >
        <TextField
          label="Request identifier"
          value={requestId}
          onChange={onRequestId}
          required
        />
        <TextField
          label="Tracking token"
          value={trackingToken}
          onChange={onTrackingToken}
          required
        />
        <div>
          <SubmitButton pending={pending}>Check</SubmitButton>
        </div>
      </form>

      {failure === undefined ? null : (
        <ErrorAlert message={describeError(failure)} />
      )}

      {result === undefined ? null : (
        <div className="border-base-300 border-t pt-3">
          <DetailList>
            <DetailRow label="Status">
              <StatusBadge tone={toneForStatus(result.request.status)}>
                {result.request.status}
              </StatusBadge>
            </DetailRow>
            <DetailRow label="App">{result.request.name}</DetailRow>
            <DetailRow label="Submitted">
              {formatInstant(result.request.submittedAt)}
            </DetailRow>
            <DetailRow label="Scopes asked for">
              <Chips values={result.request.requestedScopes} />
            </DetailRow>
            {result.request.decisionNote === null ? null : (
              <DetailRow label="Note from the reviewer">
                {/* A detail row's value is usually an identifier or a chip that
                    sets its own size, which is why the row stays at 14px. This
                    one is a sentence somebody wrote to be read, so it takes the
                    prose floor and is marked for the assertion that holds it. */}
                <span data-prose className="max-sm:text-base">
                  {result.request.decisionNote}
                </span>
              </DetailRow>
            )}
            {result.clientId === undefined ? null : (
              <DetailRow label="Client identifier">
                <CopyableValue
                  value={result.clientId}
                  label="client identifier"
                />
              </DetailRow>
            )}
            {result.issuer === undefined ? null : (
              <DetailRow label="Issuer">
                <CopyableValue value={result.issuer} label="issuer" />
              </DetailRow>
            )}
            {result.wellKnown === undefined ? null : (
              <DetailRow label="SMART configuration">
                <CopyableValue value={result.wellKnown} label="discovery URL" />
              </DetailRow>
            )}
          </DetailList>

          {result.request.status === "approved" ? (
            <div className="mt-3">
              <InfoAlert>
                If your app needs a client secret, the administrator who
                approved this request has it: it is shown to them once and
                cannot be read again from here.
              </InfoAlert>
            </div>
          ) : null}
        </div>
      )}
    </Panel>
  );
}
