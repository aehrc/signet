/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Validation of an `/authorize` request.
 *
 * Pure, and deliberately the whole of step 1 of the authorization flow: every
 * refusal the authorization endpoint can produce before a user is involved is
 * decided here, from parameters and two configuration rows, with no I/O. That
 * makes the entire rejection surface - the part a conformance reviewer and an
 * attacker both care about - unit testable without a database.
 *
 * Two properties of the ordering are load-bearing.
 *
 * The client and the redirect URI are validated first, and their failures are
 * reported *directly* to the browser rather than by redirecting. RFC 6749
 * §4.1.2.1 requires this: redirecting an error to an unvalidated URI is an open
 * redirector, and it hands an attacker a way to have the authorization server
 * itself deliver a payload to a destination of their choosing. Everything after
 * that point redirects, because by then the destination has been proved to
 * belong to the registered client.
 *
 * Capability flags gate the request as well as the discovery document. An
 * endpoint that does not advertise `permission-patient` refuses a `patient/`
 * scope here, so the `capabilities` array cannot be a lie in either direction -
 * which is the property the conformance suite asserts.
 *
 * @see https://hl7.org/fhir/smart-app-launch/app-launch.html
 *
 * Author: John Grimes
 */

import { parseScopes, areScopesCoveredBy } from "@signet/core";

import { checkAudience } from "./audience.js";
import { contextRequirements } from "./contextRequirements.js";
import { matchRedirectUri } from "./redirectUri.js";

import type { AuthorizeErrorCode } from "../http/oauthErrors.js";
import type { ClientType, Scope } from "@signet/core";

/**
 * The `/authorize` request parameters Signet reads.
 *
 * Every field is `string | undefined` rather than merely optional, because the
 * caller builds this by reading each name out of a query string or a form body and
 * gets `undefined` for the ones that are absent. Under
 * `exactOptionalPropertyTypes` an optional-only property would reject that, and the
 * workaround - conditionally spreading ten fields - would add nothing but noise.
 */
export interface AuthorizeParams {
  readonly responseType?: string | undefined;
  readonly clientId?: string | undefined;
  readonly redirectUri?: string | undefined;
  readonly scope?: string | undefined;
  readonly state?: string | undefined;
  readonly aud?: string | undefined;
  /** The single-use handle minted by an EHR. Its presence means an EHR launch. */
  readonly launch?: string | undefined;
  readonly codeChallenge?: string | undefined;
  readonly codeChallengeMethod?: string | undefined;
  readonly nonce?: string | undefined;
}

/**
 * The client fields the decision depends on.
 *
 * A structural subset of the `clients` row, so a caller passes the row straight
 * in, and this module needs no dependency on the data layer.
 */
export interface AuthorizeClient {
  readonly clientId: string;
  readonly clientType: ClientType;
  readonly status: string;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly string[];
  readonly allowedScopes: readonly string[];
}

/** The endpoint fields the decision depends on. A subset of the row. */
export interface AuthorizeEndpoint {
  readonly status: string;
  readonly fhirBaseUrl: string;
  readonly supportsEhrLaunch: boolean;
  readonly supportsStandaloneLaunch: boolean;
  readonly allowsPublicClients: boolean;
  readonly allowsConfidentialSymmetricClients: boolean;
  readonly allowsConfidentialAsymmetricClients: boolean;
  readonly supportsOpenIdConnect: boolean;
  readonly supportsStandalonePatientContext: boolean;
  readonly supportsStandaloneEncounterContext: boolean;
  readonly supportsOfflineAccess: boolean;
  readonly supportsOnlineAccess: boolean;
  readonly supportsPatientScopes: boolean;
  readonly supportsUserScopes: boolean;
  readonly supportsV1Scopes: boolean;
  readonly supportsV2Scopes: boolean;
}

/**
 * A refusal that cannot be redirected, because the destination is not trusted.
 *
 * Rendered as a page, not as a redirect. See the module header.
 */
export interface DirectRefusal {
  readonly mode: "direct";
  readonly error: AuthorizeErrorCode;
  readonly description: string;
}

/** A refusal delivered to the client's validated redirect URI. */
export interface RedirectRefusal {
  readonly mode: "redirect";
  readonly redirectUri: string;
  readonly error: AuthorizeErrorCode;
  readonly description: string;
  readonly state?: string;
}

/** Either kind of `/authorize` refusal. */
export type AuthorizeRefusal = DirectRefusal | RedirectRefusal;

/** Which SMART launch mode the request is using. */
export type LaunchMode = "ehr" | "standalone";

/** An `/authorize` request that passed every pre-authentication check. */
export interface ValidatedAuthorizeRequest {
  readonly clientId: string;
  readonly clientType: ClientType;
  /** The URI to bind the code to and to redirect to. As presented. */
  readonly redirectUri: string;
  readonly state: string | undefined;
  readonly nonce: string | undefined;
  readonly aud: string;
  readonly codeChallenge: string;
  /** Only `S256` is accepted, so this is a constant - kept for the session row. */
  readonly codeChallengeMethod: "S256";
  /** Raw scope strings in requested order, for the session row and the audit. */
  readonly requestedScopes: readonly string[];
  /** The same scopes parsed, with v1 suffixes normalised to v2. */
  readonly scopes: readonly Scope[];
  /** The EHR's launch handle. Present exactly when `launchMode` is `ehr`. */
  readonly launch: string | undefined;
  readonly launchMode: LaunchMode;
  /** Whether resolving the authorization requires a patient in context. */
  readonly requestsPatientContext: boolean;
  /** Whether resolving the authorization requires an encounter in context. */
  readonly requestsEncounterContext: boolean;
}

/** The outcome of validating an `/authorize` request. */
export type AuthorizeValidation =
  | { readonly ok: true; readonly request: ValidatedAuthorizeRequest }
  | { readonly ok: false; readonly refusal: AuthorizeRefusal };

/** Everything the validation reads. */
export interface AuthorizeValidationInput {
  readonly params: AuthorizeParams;
  readonly endpoint: AuthorizeEndpoint;
  /** Undefined when `client_id` named no client on this endpoint. */
  readonly client: AuthorizeClient | undefined;
}

/**
 * A PKCE `code_challenge` in its S256 form: the base64url encoding of a SHA-256
 * digest, which is always 43 unpadded characters.
 */
const S256_CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/;

/** Human-readable explanation of each redirect URI refusal. */
const REDIRECT_URI_DESCRIPTIONS = {
  missing: "redirect_uri is required",
  malformed: "redirect_uri is not an absolute URI",
  "none-registered": "This client has no registered redirect URIs",
  "no-match": "redirect_uri does not match a registered value",
} as const;

/** Builds a refusal that must be rendered rather than redirected. */
function direct(
  error: AuthorizeErrorCode,
  description: string,
): AuthorizeValidation {
  return { ok: false, refusal: { mode: "direct", error, description } };
}

/**
 * Whether the endpoint accepts this posture of client at all.
 *
 * Separate from the policy: an endpoint that does not advertise
 * `client-public` must refuse a public client before any policy runs, because
 * the discovery document promised it would.
 */
function endpointAllowsClientType(
  endpoint: AuthorizeEndpoint,
  clientType: ClientType,
): boolean {
  switch (clientType) {
    case "public": {
      return endpoint.allowsPublicClients;
    }
    case "confidential-symmetric": {
      return endpoint.allowsConfidentialSymmetricClients;
    }
    case "confidential-asymmetric": {
      return endpoint.allowsConfidentialAsymmetricClients;
    }
  }
}

/**
 * Whether a raw scope string uses a SMART v1 permission suffix.
 *
 * Detected on the raw string, because `parseScope` normalises `.read` to `.rs`
 * and the fact that it *was* v1 is gone by the time the parsed scope exists. An
 * endpoint that does not advertise `permission-v1` has to be able to refuse it.
 */
function isV1ResourceScope(raw: string): boolean {
  return /^(?:patient|user|system)\/[^.]+\.(?:read|write|\*)$/.test(raw);
}

/** Whether a raw scope string uses a v2 `cruds` permission suffix. */
function isV2ResourceScope(raw: string): boolean {
  return (
    /^(?:patient|user|system)\/[^.]+\.[cruds]+(?:\?.*)?$/.test(raw) &&
    !isV1ResourceScope(raw)
  );
}

/**
 * Finds the first requested scope the endpoint's capabilities forbid.
 *
 * Returns a description rather than the scope, because the caller only ever puts
 * it in an `error_description`, and building the sentence at the point that knows
 * why* keeps that knowledge out of the handler.
 */
function unsupportedScope(
  endpoint: AuthorizeEndpoint,
  raw: readonly string[],
  scopes: readonly Scope[],
): string | undefined {
  for (const value of raw) {
    if (isV1ResourceScope(value) && !endpoint.supportsV1Scopes) {
      return `This endpoint does not accept SMART v1 scopes ("${value}")`;
    }
    if (isV2ResourceScope(value) && !endpoint.supportsV2Scopes) {
      return `This endpoint does not accept SMART v2 scopes ("${value}")`;
    }
  }

  for (const scope of scopes) {
    switch (scope.kind) {
      case "resource": {
        if (scope.context === "patient" && !endpoint.supportsPatientScopes) {
          return "This endpoint does not accept patient-context scopes";
        }
        if (scope.context === "user" && !endpoint.supportsUserScopes) {
          return "This endpoint does not accept user-context scopes";
        }
        break;
      }
      case "identity": {
        if (scope.name === "openid" && !endpoint.supportsOpenIdConnect) {
          return "This endpoint does not support OpenID Connect";
        }
        break;
      }
      case "refresh": {
        if (
          scope.name === "offline_access" &&
          !endpoint.supportsOfflineAccess
        ) {
          return "This endpoint does not issue offline_access refresh tokens";
        }
        if (scope.name === "online_access" && !endpoint.supportsOnlineAccess) {
          return "This endpoint does not issue online_access refresh tokens";
        }
        break;
      }
      default: {
        break;
      }
    }
  }

  return undefined;
}

/**
 * Parses the client's `allowed_scopes` for the allowlist comparison.
 *
 * Unparseable entries are dropped rather than failing the request: they are the
 * operator's mistake, not the app's, and the effect of dropping one is that the
 * app is refused a scope it would otherwise have been allowed - which is the safe
 * direction. The console validates the allowlist when it is edited.
 */
function parseAllowlist(allowed: readonly string[]): readonly Scope[] {
  return parseScopes(allowed.join(" ")).scopes;
}

/**
 * Validates an `/authorize` request.
 *
 * @param input - The parameters plus the client and endpoint they name.
 */
export function validateAuthorizeRequest(
  input: AuthorizeValidationInput,
): AuthorizeValidation {
  const { params, endpoint, client } = input;

  // ---------------------------------------------------------------------------
  // Refusals that must not redirect.
  // ---------------------------------------------------------------------------

  if (params.clientId === undefined || params.clientId.length === 0) {
    return direct("invalid_request", "client_id is required");
  }
  if (client === undefined) {
    return direct(
      "invalid_request",
      "client_id is not registered on this endpoint",
    );
  }

  const redirect = matchRedirectUri(
    params.redirectUri,
    client.redirectUris,
    client.clientType,
  );
  if (!redirect.ok) {
    return direct(
      "invalid_request",
      REDIRECT_URI_DESCRIPTIONS[redirect.reason],
    );
  }

  // ---------------------------------------------------------------------------
  // From here the destination is proved, so refusals redirect.
  // ---------------------------------------------------------------------------

  const state = params.state;
  const refuse = (
    error: AuthorizeErrorCode,
    description: string,
  ): AuthorizeValidation => ({
    ok: false,
    refusal: {
      mode: "redirect",
      redirectUri: redirect.redirectUri,
      error,
      description,
      ...(state === undefined ? {} : { state }),
    },
  });

  if (endpoint.status !== "active") {
    return refuse(
      "temporarily_unavailable",
      "This endpoint is not currently accepting authorization requests",
    );
  }

  if (params.responseType !== "code") {
    return refuse(
      "unsupported_response_type",
      "Only response_type=code is supported",
    );
  }

  if (client.status !== "active") {
    return refuse(
      "unauthorized_client",
      `This client's registration is ${client.status}`,
    );
  }
  if (!client.grantTypes.includes("authorization_code")) {
    return refuse(
      "unauthorized_client",
      "This client is not registered for the authorization_code grant",
    );
  }
  if (!endpointAllowsClientType(endpoint, client.clientType)) {
    return refuse(
      "unauthorized_client",
      `This endpoint does not accept ${client.clientType} clients`,
    );
  }

  // PKCE is mandatory for every client, including confidential ones. SMART 2.0
  // requires it, and it is the only defence a public client has against a stolen
  // authorization code.
  if (
    params.codeChallengeMethod === undefined ||
    params.codeChallengeMethod.length === 0
  ) {
    return refuse(
      "invalid_request",
      "code_challenge_method=S256 is required; PKCE is mandatory",
    );
  }
  if (params.codeChallengeMethod !== "S256") {
    return refuse(
      "invalid_request",
      `code_challenge_method must be S256, not ${params.codeChallengeMethod}`,
    );
  }
  if (
    params.codeChallenge === undefined ||
    !S256_CHALLENGE_PATTERN.test(params.codeChallenge)
  ) {
    return refuse(
      "invalid_request",
      "code_challenge must be the base64url-encoded SHA-256 of the verifier",
    );
  }

  const audience = checkAudience(params.aud, endpoint.fhirBaseUrl);
  if (!audience.ok) {
    return refuse(
      "invalid_request",
      audience.reason === "missing"
        ? "aud is required and must be this endpoint's FHIR base URL"
        : "aud is not this endpoint's FHIR base URL",
    );
  }

  if (params.scope === undefined || params.scope.trim().length === 0) {
    return refuse("invalid_scope", "scope is required");
  }

  const parsed = parseScopes(params.scope);
  const firstRejected = parsed.rejected[0];
  if (firstRejected !== undefined) {
    return refuse(
      "invalid_scope",
      `Could not parse scope "${firstRejected.raw}": ${firstRejected.message}`,
    );
  }
  if (parsed.scopes.length === 0) {
    return refuse("invalid_scope", "scope is required");
  }

  const requestedScopes = params.scope
    .split(/\s+/)
    .filter((value) => value.length > 0);

  const unsupported = unsupportedScope(
    endpoint,
    requestedScopes,
    parsed.scopes,
  );
  if (unsupported !== undefined) {
    return refuse("invalid_scope", unsupported);
  }

  if (
    !areScopesCoveredBy(parsed.scopes, parseAllowlist(client.allowedScopes))
  ) {
    return refuse(
      "invalid_scope",
      "The request includes scopes outside this client's allowlist",
    );
  }

  // ---------------------------------------------------------------------------
  // Launch mode.
  // ---------------------------------------------------------------------------

  const wantsLaunchHandle = parsed.scopes.some(
    (scope) => scope.kind === "launch" && scope.resource === undefined,
  );
  const hasLaunchHandle =
    params.launch !== undefined && params.launch.length > 0;

  if (hasLaunchHandle && !endpoint.supportsEhrLaunch) {
    return refuse(
      "invalid_request",
      "This endpoint does not support the EHR launch",
    );
  }
  if (!hasLaunchHandle && !endpoint.supportsStandaloneLaunch) {
    return refuse(
      "invalid_request",
      "This endpoint does not support the standalone launch",
    );
  }
  // The bare `launch` scope means "give me the context from the EHR", and there
  // is no context to give without a handle. Refusing is better than issuing a
  // token whose missing context the app only discovers at its first API call.
  if (wantsLaunchHandle && !hasLaunchHandle) {
    return refuse(
      "invalid_request",
      "The launch scope requires a launch parameter naming an EHR launch context",
    );
  }

  const launchMode: LaunchMode = hasLaunchHandle ? "ehr" : "standalone";
  const requirements = contextRequirements(parsed.scopes);
  const needsPatient = requirements.patient;
  const needsEncounter = requirements.encounter;

  if (
    launchMode === "standalone" &&
    needsPatient &&
    !endpoint.supportsStandalonePatientContext
  ) {
    return refuse(
      "invalid_scope",
      "This endpoint does not support patient context in a standalone launch",
    );
  }
  if (
    launchMode === "standalone" &&
    needsEncounter &&
    !endpoint.supportsStandaloneEncounterContext
  ) {
    return refuse(
      "invalid_scope",
      "This endpoint does not support encounter context in a standalone launch",
    );
  }

  return {
    ok: true,
    request: {
      clientId: client.clientId,
      clientType: client.clientType,
      redirectUri: redirect.redirectUri,
      state,
      nonce: params.nonce,
      aud: audience.audience,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: "S256",
      requestedScopes,
      scopes: parsed.scopes,
      launch: hasLaunchHandle ? params.launch : undefined,
      launchMode,
      requestsPatientContext: needsPatient,
      requestsEncounterContext: needsEncounter,
    },
  };
}
