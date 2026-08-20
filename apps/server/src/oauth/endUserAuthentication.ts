/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Authenticating an end user, in the one place both surfaces use.
 *
 * The authorization flow's login step and the management page's sign-in accept the same
 * two credentials against the same accounts, and there is no version of this that should
 * differ between them. Two copies would have meant two chances to get the timing
 * equalisation wrong, or to relax the persona rule on one surface and not the other.
 *
 * Two rules are load-bearing.
 *
 * A missing account costs what a wrong password costs. Argon2id verification dominates
 * the work, so a path that skipped it when the username was unknown would answer
 * measurably faster - turning user enumeration into a timing measurement rather than a
 * guess. The verification therefore runs against an unmatchable hash when no account was
 * found, and only then is the request refused.
 *
 * A persona is selectable only on a non-production endpoint. That is checked by the data
 * layer's `isPersonaSelectable`, which reads both the endpoint's flag and the account's,
 * so neither can be relaxed alone.
 *
 * Author: John Grimes
 */

import {
  findEndUserByUsername,
  getEndUser,
  isEndUserEnabled,
  isPersonaSelectable,
  verifyPassword,
  withTenantScope,
} from "@signet/db";

import { UNMATCHABLE_PASSWORD_HASH } from "../security/passwordTiming.js";

import type { Database, Endpoint, EndpointScope, EndUser } from "@signet/db";

/** What a sign-in body may carry. Every field is unvalidated input. */
export interface EndUserCredentials {
  readonly username?: unknown;
  readonly password?: unknown;
  readonly personaId?: unknown;
}

/**
 * Reads a sign-in body.
 *
 * Both surfaces accept the same three fields and neither validates them here - the
 * fields are `unknown` all the way into {@link authenticateEndUser}, which is what
 * makes the type checker insist on a `typeof` test before any of them is used. A
 * body that is not JSON at all becomes an empty object and is refused as "no
 * credential", which is the right answer to a request that supplied none.
 *
 * @param c - The request.
 * @param c.req - Hono's request accessor.
 * @param c.req.json - Parses the body.
 */
export async function readEndUserCredentials(c: {
  readonly req: { json: () => Promise<unknown> };
}): Promise<EndUserCredentials> {
  return (await c.req.json().catch(() => ({}))) as EndUserCredentials;
}

/** Why an end user sign-in was refused. */
export type EndUserAuthenticationRefusal =
  /** No credential of either recognised shape was supplied. */
  | "no-credential"
  /** A persona was named that this endpoint will not admit. */
  | "persona-not-selectable"
  /** The username or the password was wrong, or the account is disabled. */
  | "password-rejected";

/** The outcome of an attempt. */
export type EndUserAuthentication =
  | { readonly ok: true; readonly user: EndUser }
  | { readonly ok: false; readonly reason: EndUserAuthenticationRefusal };

/**
 * Authenticates an end user by password or by persona.
 *
 * @param db - The connection to use.
 * @param scope - The endpoint the account must belong to.
 * @param endpoint - The endpoint's configuration, for the persona rule.
 * @param credentials - The request body, unvalidated.
 */
export async function authenticateEndUser(
  db: Database,
  scope: EndpointScope,
  endpoint: Endpoint,
  credentials: EndUserCredentials,
): Promise<EndUserAuthentication> {
  const personaId = credentials.personaId;
  if (typeof personaId === "string") {
    const persona = await withTenantScope(db, scope, (bound) =>
      getEndUser(bound, personaId),
    );
    // Both halves of the persona rule are checked by one pure predicate, so neither the
    // production flag nor the persona flag can be relaxed alone.
    if (persona === undefined || !isPersonaSelectable(endpoint, persona)) {
      return { ok: false, reason: "persona-not-selectable" };
    }
    return { ok: true, user: persona };
  }

  const username = credentials.username;
  if (
    typeof username !== "string" ||
    typeof credentials.password !== "string"
  ) {
    return { ok: false, reason: "no-credential" };
  }

  const candidate = await withTenantScope(db, scope, (bound) =>
    findEndUserByUsername(bound, username),
  );
  // Verified even when the account does not exist, against a hash that cannot match, so
  // that a missing account and a wrong password take the same time. See the header.
  const matches = await verifyPassword(
    credentials.password,
    candidate?.passwordHash ?? UNMATCHABLE_PASSWORD_HASH,
  );

  if (
    candidate === undefined ||
    candidate.passwordHash === null ||
    !matches ||
    !isEndUserEnabled(candidate)
  ) {
    return { ok: false, reason: "password-rejected" };
  }
  return { ok: true, user: candidate };
}

/** A refusal that is answered rather than audited as a credential failure. */
export interface EndUserAuthenticationProblem {
  readonly code: "invalid_request";
  readonly description: string;
}

/** An OAuth-shaped refusal body, ready to be answered with. */
export interface EndUserSignInRefusal {
  readonly ok: false;
  readonly status: 400 | 401;
  readonly body: {
    readonly error: string;
    readonly error_description: string;
  };
}

/** What a sign-in attempt produced. */
export type EndUserSignIn =
  { readonly ok: true; readonly user: EndUser } | EndUserSignInRefusal;

/**
 * Authenticates an end user and decides what to answer when it fails.
 *
 * Both surfaces make the same three-way decision - admitted, told what to supply, or
 * refused - and the third case must look identical to the second-to-last for user
 * enumeration to stay impossible. Deciding it here means one message and one status for
 * every credential failure on either surface, rather than two copies that drift.
 *
 * The audit event differs between the surfaces, since one names the authorization session
 * it belongs to and the other does not, so recording it is the caller's callback. It is
 * invoked only for a credential failure: being told to supply a credential is not a
 * failed sign-in and should not read as one in the trail.
 *
 * @param options - The connection, the endpoint, the credentials and the audit callback.
 * @param options.db - The connection to use.
 * @param options.scope - The endpoint the account must belong to.
 * @param options.endpoint - The endpoint's configuration.
 * @param options.credentials - The request body, unvalidated.
 * @param options.recordFailure - Audits a credential failure.
 */
export async function signInEndUser(options: {
  readonly db: Database;
  readonly scope: EndpointScope;
  readonly endpoint: Endpoint;
  readonly credentials: EndUserCredentials;
  readonly recordFailure: (
    reason: EndUserAuthenticationRefusal,
  ) => Promise<void>;
}): Promise<EndUserSignIn> {
  const authenticated = await authenticateEndUser(
    options.db,
    options.scope,
    options.endpoint,
    options.credentials,
  );
  if (authenticated.ok) {
    return authenticated;
  }

  const problem = endUserAuthenticationProblem(
    authenticated.reason,
    options.endpoint.authMode,
  );
  if (problem !== undefined) {
    return {
      ok: false,
      status: 400,
      body: { error: problem.code, error_description: problem.description },
    };
  }

  await options.recordFailure(authenticated.reason);
  return {
    ok: false,
    status: 401,
    body: {
      error: "invalid_request",
      error_description: "Those credentials were not accepted",
    },
  };
}

/**
 * The answer for a refusal that is not a wrong credential.
 *
 * Two cases, and both are the caller being told what to do rather than being refused: no
 * credential of either shape was supplied, and an endpoint that federates authentication
 * has no local password to check. Everything else is a credential failure, which both
 * surfaces audit and answer with one uniform message - so this returns undefined for it.
 *
 * @param reason - Why the attempt failed.
 * @param authMode - The endpoint's `auth_mode`.
 */
export function endUserAuthenticationProblem(
  reason: EndUserAuthenticationRefusal,
  authMode: string,
): EndUserAuthenticationProblem | undefined {
  if (reason === "no-credential") {
    return {
      code: "invalid_request",
      description: "Supply either username and password, or personaId",
    };
  }
  if (reason === "password-rejected" && authMode === "oidc") {
    return {
      code: "invalid_request",
      description:
        "This endpoint federates authentication to an upstream identity provider",
    };
  }
  return undefined;
}
