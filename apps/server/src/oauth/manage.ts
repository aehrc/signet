/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The management endpoint: what an end user can see and withdraw.
 *
 * SMART's `management_endpoint` is advertised in the discovery document as "where a
 * user can review and revoke the access they have granted". This is the API behind
 * that page.
 *
 * It needs its own authentication, and that is the reason `end_user_sessions` exists.
 * An end user reviewing their authorizations is not in the middle of an authorization,
 * so there is no `authorization_sessions` row to hang the identity off - and the
 * console's admin session is a different credential belonging to a different kind of
 * person.
 *
 * Withdrawing access does two things, and both are necessary. Revoking the stored
 * consent stops the *next* authorization from being silent; revoking the tokens stops
 * the *current* one. Doing only the first leaves an app working for as long as its
 * access token lasts, which is not what a person pressing "disconnect" means.
 *
 * The session cookie is scoped to the endpoint's own path, so a session on one endpoint
 * is not sent to another. Two endpoints of the same tenant hold separate accounts with
 * separate passwords, and a cookie shared between them would make one password admit
 * the holder to both.
 *
 * Author: John Grimes
 */

import { buildAppAccess } from "@signet/core";
import {
  clientScopeFromRow,
  createEndUserSession,
  findLiveEndUserSession,
  generateOpaqueToken,
  getClientByClientId,
  hashToken,
  listAccessTokensForSubject,
  listClients,
  listConsentsForEndUser,
  listRefreshTokensForSubject,
  revokeAccessTokensForSubjectAndClient,
  revokeConsentsForClient,
  revokeEndUserSession,
  revokeRefreshTokensForSubjectAndClient,
  withTenantScope,
} from "@signet/db";

import {
  readEndUserCredentials,
  signInEndUser,
} from "./endUserAuthentication.js";
import {
  cookiesAreSecure,
  readCookie,
  sessionCookieHeader,
} from "../http/cookies.js";
import { requestMetadata } from "../http/requestMeta.js";

import type {
  ResolvedIssuerContext,
  ServerContext,
  SignetEnvironment,
} from "../context.js";
import type { IssuedToken } from "@signet/core";
import type { AuthenticatedEndUser } from "@signet/db";
import type { Context } from "hono";

/**
 * How long an end user's management session lasts, in seconds.
 *
 * One hour. Shorter than the console's twelve, because this is a page a patient may
 * open on a shared or borrowed device, and the work it exists for - reviewing a list and
 * withdrawing one entry - takes minutes.
 */
export const MANAGE_SESSION_TTL_SECONDS = 3600;

/** Name of the cookie carrying an end user's session. */
export const MANAGE_COOKIE_NAME = "signet_end_user";

/**
 * Builds the `Set-Cookie` value for a management session.
 *
 * The attributes come from the shared helper; what is specific here is the path. It is
 * the endpoint's own issuer path rather than `/`, which is what keeps a session on one
 * endpoint from being presented to another - the two hold separate accounts with
 * separate passwords.
 *
 * @param value - The session token, or an empty string to clear it.
 * @param issuer - The endpoint's issuer identifier.
 * @param options - How the cookie should be scoped.
 * @param options.secure - Whether to mark the cookie `Secure`.
 * @param options.maxAgeSeconds - Lifetime in seconds. Zero clears the cookie.
 */
export function manageCookie(
  value: string,
  issuer: string,
  options: { readonly secure: boolean; readonly maxAgeSeconds: number },
): string {
  return sessionCookieHeader(MANAGE_COOKIE_NAME, value, {
    path: issuerPath(issuer),
    secure: options.secure,
    maxAgeSeconds: options.maxAgeSeconds,
  });
}

/**
 * The path an endpoint's cookie is scoped to.
 *
 * Derived from the issuer rather than from the request, so it cannot be influenced by
 * how the browser happened to reach the server.
 *
 * @param issuer - The endpoint's issuer identifier.
 */
export function issuerPath(issuer: string): string {
  return new URL(issuer).pathname;
}

/** The refusal an unauthenticated management request gets. */
function unauthenticated(c: Context<SignetEnvironment>) {
  return c.json(
    {
      error: "unauthenticated",
      error_description: "Sign in to review the access you have granted",
    },
    401,
  );
}

/** Resolves the management session, or answers 401. */
async function authenticate(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
): Promise<AuthenticatedEndUser | Response> {
  const presented = readCookie(c.req.header("cookie"), MANAGE_COOKIE_NAME);
  if (presented === undefined) {
    return unauthenticated(c);
  }
  const session = await withTenantScope(
    context.db,
    issuerContext.scope,
    async (bound) =>
      findLiveEndUserSession(
        bound,
        await hashToken(presented),
        context.clock(),
      ),
  );
  return session ?? unauthenticated(c);
}

/**
 * Handles `POST {iss}/manage/session`: signs an end user in.
 *
 * The same two credentials the authorization flow accepts - a local password, or a
 * persona on a non-production endpoint - because they are the same accounts. A persona
 * has no password by design, and refusing it here would mean a connectathon endpoint
 * whose management page nobody could open.
 *
 * @param context - The server's dependencies.
 */
export function manageSignInHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint } = issuerContext;
    const metadata = requestMetadata(c);

    const body = await readEndUserCredentials(c);

    const authenticated = await signInEndUser({
      db: context.db,
      scope: issuerContext.scope,
      endpoint,
      credentials: body,
      // Marked with the surface, because a failure here is someone at the management page
      // rather than an app's authorization, and an operator reading the trail wants to
      // know which.
      recordFailure: async (reason) => {
        await context.audit.record(context.db, {
          tenantId: issuerContext.tenant.id,
          endpointId: endpoint.id,
          endpointSlug: endpoint.slug,
          actor: { type: "end-user" },
          action: "end-user.login-failed",
          target: { type: "end-user" },
          detail: { reason, surface: "management" },
          ...metadata,
        });
      },
    });
    if (!authenticated.ok) {
      return c.json(authenticated.body, authenticated.status);
    }
    const user = authenticated.user;

    const token = generateOpaqueToken();
    await withTenantScope(context.db, issuerContext.scope, async (bound) =>
      createEndUserSession(bound, {
        endUserId: user.id,
        tokenHash: await hashToken(token),
        expiresAt: new Date(
          context.clock().getTime() + MANAGE_SESSION_TTL_SECONDS * 1000,
        ),
        ip: metadata.ip ?? null,
        userAgent: metadata.userAgent ?? null,
      }),
    );

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
      actor: {
        type: "end-user",
        id: user.id,
        displayName: user.displayName,
      },
      action: "end-user.login",
      target: { type: "end-user", id: user.id },
      detail: { surface: "management", persona: user.isPersona },
      ...metadata,
    });

    c.header(
      "Set-Cookie",
      manageCookie(token, issuerContext.issuer, {
        secure: cookiesAreSecure(context.config.publicUrl),
        maxAgeSeconds: MANAGE_SESSION_TTL_SECONDS,
      }),
    );
    c.header("Cache-Control", "no-store");
    return c.json({
      user: {
        displayName: user.displayName,
        username: user.username,
        fhirUser: user.fhirUserReference,
      },
    });
  };
}

/**
 * Handles `DELETE {iss}/manage/session`: signs an end user out.
 *
 * @param context - The server's dependencies.
 */
export function manageSignOutHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const presented = readCookie(c.req.header("cookie"), MANAGE_COOKIE_NAME);

    if (presented !== undefined) {
      await withTenantScope(context.db, issuerContext.scope, async (bound) =>
        revokeEndUserSession(
          bound,
          await hashToken(presented),
          context.clock(),
        ),
      );
    }

    c.header(
      "Set-Cookie",
      manageCookie("", issuerContext.issuer, {
        secure: cookiesAreSecure(context.config.publicUrl),
        maxAgeSeconds: 0,
      }),
    );
    return c.body(null, 204);
  };
}

/**
 * Handles `GET {iss}/manage`: what this person has granted, and to whom.
 *
 * The list merges two records of access, because either can exist without the other.
 * Stored consents are the standing grants of a `remember`-mode endpoint, included
 * even when revoked or expired and marked - a page that dropped them would look, to
 * somebody who had just withdrawn access, as though the record had been lost rather
 * than ended. Live tokens are the only record an `always`-mode endpoint keeps, so an
 * app holding one is listed too, or the page would say "no apps have access" while
 * apps hold usable tokens. The merge itself is `buildAppAccess` in `@signet/core`.
 *
 * @param context - The server's dependencies.
 */
export function manageAuthorizationsHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const authenticated = await authenticate(c, context, issuerContext);
    if (authenticated instanceof Response) {
      return authenticated;
    }
    const { user } = authenticated;

    const consents = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => listConsentsForEndUser(bound, user.id),
    );
    const accessTokens = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => listAccessTokensForSubject(bound, user.id),
    );
    const refreshTokens = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => listRefreshTokensForSubject(bound, user.id),
    );
    const clients = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => listClients(bound),
    );

    const view = buildAppAccess({
      consents: consents.map((entry) => ({
        consentId: entry.consent.id,
        clientId: entry.client.clientId,
        clientName: entry.client.name,
        logoUrl: entry.client.logoUrl,
        scope: entry.consent.scope,
        grantedAt: entry.consent.grantedAt,
        expiresAt: entry.consent.expiresAt,
        revokedAt: entry.consent.revokedAt,
      })),
      accessTokens: accessTokens.map(issuedTokenView),
      refreshTokens: refreshTokens.map(issuedTokenView),
      clients: clients.map((client) => ({
        rowId: client.id,
        clientId: client.clientId,
        name: client.name,
        logoUrl: client.logoUrl,
      })),
      now: context.clock(),
    });

    c.header("Cache-Control", "no-store");
    return c.json({
      user: {
        displayName: user.displayName,
        username: user.username,
        fhirUser: user.fhirUserReference,
      },
      authorizations: view.entries,
      liveTokens: view.liveTokens,
    });
  };
}

/** The lifecycle half of a token row, which is all the merge needs. */
function issuedTokenView(token: {
  readonly clientId: string;
  readonly scope: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
}): IssuedToken {
  return {
    clientRowId: token.clientId,
    scope: token.scope,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
    revokedAt: token.revokedAt,
  };
}

/**
 * Handles `POST {iss}/manage/revoke`: withdraws one app's access.
 *
 * Consent and tokens together - see the module header for why either alone is the
 * wrong answer.
 *
 * @param context - The server's dependencies.
 */
export function manageRevokeHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);
    const authenticated = await authenticate(c, context, issuerContext);
    if (authenticated instanceof Response) {
      return authenticated;
    }
    const { user } = authenticated;

    const body = (await c.req.json().catch(() => ({}))) as {
      clientId?: unknown;
    };
    const requestedClientId = body.clientId;
    if (typeof requestedClientId !== "string") {
      return c.json(
        { error: "invalid_request", error_description: "clientId is required" },
        400,
      );
    }

    const client = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => getClientByClientId(bound, requestedClientId),
    );
    if (client === undefined) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "No such app on this endpoint",
        },
        404,
      );
    }

    const clientScope = clientScopeFromRow(issuerContext.scope, client);
    const now = context.clock();
    const consentsRevoked = await withTenantScope(
      context.db,
      clientScope,
      (bound) => revokeConsentsForClient(bound, user.id, now),
    );
    // Scoped to this user *and* this client: revoking every token the user holds
    // would disconnect apps they did not ask to disconnect.
    const accessRevoked = await withTenantScope(
      context.db,
      clientScope,
      (bound) => revokeAccessTokensForSubjectAndClient(bound, user.id, now),
    );
    const refreshRevoked = await withTenantScope(
      context.db,
      clientScope,
      (bound) => revokeRefreshTokensForSubjectAndClient(bound, user.id, now),
    );

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: issuerContext.endpoint.id,
      endpointSlug: issuerContext.endpoint.slug,
      actor: {
        type: "end-user",
        id: user.id,
        displayName: user.displayName,
      },
      action: "consent.revoked",
      target: { type: "client", id: client.clientId },
      detail: {
        consentsRevoked,
        accessTokensRevoked: accessRevoked,
        refreshTokensRevoked: refreshRevoked,
        surface: "management",
      },
      ...metadata,
    });

    return c.json({
      consentsRevoked,
      accessTokensRevoked: accessRevoked,
      refreshTokensRevoked: refreshRevoked,
    });
  };
}
