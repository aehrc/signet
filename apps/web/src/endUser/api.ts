/**
 * The end-user surfaces' own API layer.
 *
 * Separate from the console's because the paths and the credential are different:
 * everything here lives under an endpoint's issuer, and the session cookie - where there
 * is one - is scoped to that issuer's path. Sharing the console's client would mean one
 * module whose base path depended on which surface called it.
 *
 * The interaction API is the interesting part. It has no credential at all: the session
 * identifier in the URL grants nothing, and every handler re-derives the current step
 * from the stored row rather than trusting the page that posted to it. So a page cannot
 * skip a step by calling the next one - it is answered with the step it is actually on,
 * which is exactly what these functions return.
 *
 * Author: John Grimes
 */

import { requestJson } from "../api/request.js";

import type { InteractionView as InteractionState } from "@signet/contracts";

export type {
  InteractionStep,
  InteractionView as InteractionState,
} from "@signet/contracts";

/** The path prefix of the endpoint the current page belongs to. */
export function issuerBase(tenant: string, endpoint: string): string {
  return `/t/${encodeURIComponent(tenant)}/e/${encodeURIComponent(endpoint)}`;
}

/**
 * Makes a request under the endpoint's issuer.
 *
 * The fetch itself is shared with the console; what differs is the refusal body, so the
 * normalisation is supplied here.
 */
async function request<T>(
  path: string,
  options: {
    readonly method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
    readonly body?: unknown;
    readonly headers?: Readonly<Record<string, string>>;
  } = {},
): Promise<T> {
  return await requestJson<T>(path, {
    ...options,
    normaliseError: normaliseOAuthError,
  });
}

/**
 * Reshapes an OAuth-style error body into the one `toApiError` reads.
 *
 * The OAuth endpoints answer with `error` and `error_description`, which is what RFC 6749
 * requires and what a client library expects. The shared error type reads `message`, so
 * the two are reconciled here rather than in the error type - the wire format is not
 * negotiable and the internal one is.
 */
function normaliseOAuthError(body: unknown): unknown {
  if (typeof body !== "object" || body === null) {
    return body;
  }
  const record = body as Record<string, unknown>;
  if (typeof record["message"] === "string") {
    return record;
  }
  return {
    ...record,
    message:
      typeof record["error_description"] === "string"
        ? record["error_description"]
        : "That request was refused",
  };
}

/** Reads the current step of an authorization. */
export async function readInteraction(
  tenant: string,
  endpoint: string,
  session: string,
): Promise<InteractionState> {
  return await request<InteractionState>(
    `${issuerBase(tenant, endpoint)}/interaction/${encodeURIComponent(session)}`,
  );
}

/** How the end user is signing in. */
export type LoginCredentials =
  | { readonly username: string; readonly password: string }
  | { readonly personaId: string };

/** Signs in, and returns whatever step the authorization is now on. */
export async function submitLogin(
  tenant: string,
  endpoint: string,
  session: string,
  credentials: LoginCredentials,
): Promise<InteractionState> {
  return await request<InteractionState>(
    `${issuerBase(tenant, endpoint)}/interaction/${encodeURIComponent(session)}/login`,
    { method: "POST", body: credentials },
  );
}

/** Records the chosen patient, and optionally encounter. */
export async function submitContext(
  tenant: string,
  endpoint: string,
  session: string,
  chosen: { readonly patient?: string; readonly encounter?: string },
): Promise<InteractionState> {
  return await request<InteractionState>(
    `${issuerBase(tenant, endpoint)}/interaction/${encodeURIComponent(session)}/context`,
    { method: "POST", body: chosen },
  );
}

/** Approves or declines the request. */
export async function submitConsent(
  tenant: string,
  endpoint: string,
  session: string,
  approve: boolean,
): Promise<InteractionState> {
  return await request<InteractionState>(
    `${issuerBase(tenant, endpoint)}/interaction/${encodeURIComponent(session)}/consent`,
    { method: "POST", body: { approve } },
  );
}

/** What the management page shows. */
export interface ManagementView {
  readonly user: {
    readonly displayName: string;
    readonly username: string;
    readonly fhirUser: string | null;
  };
  readonly authorizations: readonly {
    /** The consent behind a standing grant, or null for access backed only by tokens. */
    readonly consentId: string | null;
    readonly clientId: string;
    readonly clientName: string;
    readonly logoUrl: string | null;
    readonly scope: readonly string[];
    readonly grantedAt: string;
    readonly expiresAt: string | null;
    readonly revokedAt: string | null;
    readonly active: boolean;
    /** Whether a stored consent backs this entry, making it a standing grant. */
    readonly standing: boolean;
  }[];
  readonly liveTokens: {
    readonly access: number;
    readonly refresh: number;
  };
}

/** Signs an end user in to the management page. */
export async function manageSignIn(
  tenant: string,
  endpoint: string,
  credentials: LoginCredentials,
): Promise<{ user: ManagementView["user"] }> {
  return await request<{ user: ManagementView["user"] }>(
    `${issuerBase(tenant, endpoint)}/manage/session`,
    { method: "POST", body: credentials },
  );
}

/** Signs an end user out of the management page. */
export async function manageSignOut(
  tenant: string,
  endpoint: string,
): Promise<void> {
  await request<void>(`${issuerBase(tenant, endpoint)}/manage/session`, {
    method: "DELETE",
  });
}

/** Reads what this person has granted. */
export async function readAuthorizations(
  tenant: string,
  endpoint: string,
): Promise<ManagementView> {
  return await request<ManagementView>(
    `${issuerBase(tenant, endpoint)}/manage/authorizations`,
  );
}

/** Withdraws one app's access: its consent and its live tokens. */
export async function revokeAuthorization(
  tenant: string,
  endpoint: string,
  clientId: string,
): Promise<{
  readonly consentsRevoked: number;
  readonly accessTokensRevoked: number;
  readonly refreshTokensRevoked: number;
}> {
  return await request(`${issuerBase(tenant, endpoint)}/manage/revoke`, {
    method: "POST",
    body: { clientId },
  });
}

/** A registration request, as the portal reads it back. */
export interface PortalRequestView {
  readonly id: string;
  readonly status: "pending" | "approved" | "rejected";
  readonly name: string;
  readonly requestedScopes: readonly string[];
  readonly redirectUris: readonly string[];
  readonly submittedAt: string;
  readonly decidedAt: string | null;
  readonly decisionNote: string | null;
}

/** Files a registration request. The tracking token is returned once. */
export async function submitClientRequest(
  tenant: string,
  endpoint: string,
  payload: unknown,
): Promise<{
  readonly request: PortalRequestView;
  readonly trackingToken: string;
}> {
  return await request(`${issuerBase(tenant, endpoint)}/apps/requests`, {
    method: "POST",
    body: payload,
  });
}

/** Reads a request's state, presenting the tracking token. */
export async function readClientRequest(
  tenant: string,
  endpoint: string,
  requestId: string,
  trackingToken: string,
): Promise<{
  readonly request: PortalRequestView;
  readonly clientId?: string;
  readonly issuer?: string;
  readonly wellKnown?: string;
}> {
  // The token travels in the `Authorization` header rather than the URL, so it does not
  // end up in browser history or a server access log.
  return await request(
    `${issuerBase(tenant, endpoint)}/apps/requests/${encodeURIComponent(requestId)}`,
    { headers: { authorization: `Bearer ${trackingToken}` } },
  );
}
