/**
 * Authenticating an admin API request, and fixing the tenant it may act on.
 *
 * Three middlewares, applied in that order, and each one narrows what the request
 * can reach:
 *
 * - {@link withAdminPrincipal} establishes *who* is calling. Without it there is no
 *   principal in the request, and every handler below reads one.
 * - {@link withAdminTenant} turns `/tenants/:tenantSlug` into a `TenantScope`, which
 *   is the capability `@signet/db` requires before it will answer any question about
 *   tenant-owned data. A caller who is not a member of the named tenant gets a 404 —
 *   the same answer as for a tenant that does not exist, so the API cannot be used
 *   to enumerate tenant slugs.
 * - {@link withAdminEndpoint} narrows that scope to one endpoint.
 *
 * Role checks are separate ({@link requireRole}) because they vary per route rather
 * than per resource: listing an endpoint's clients and deleting one are the same
 * resource and different authority.
 *
 * Both credentials are presented as digests to the database. A session cookie and a
 * personal access token are hashed before they are looked up, so a disclosure of
 * either table yields nothing replayable.
 */

import { endpointUrls } from "@signet/core";
import {
  endpointScopeFromRow,
  findLiveAdminSession,
  findLiveApiToken,
  getEndpointBySlug,
  hashToken,
  resolveTenantScopeForMember,
  roleAtLeast,
  touchApiToken,
} from "@signet/db";

import { readCookie, SESSION_COOKIE_NAME } from "./cookies.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { bearerToken } from "../http/bearer.js";
import { issuerFor } from "../oauth/issuer.js";

import type { AdminPrincipal } from "./principal.js";
import type { ServerContext, SignetEnvironment } from "../context.js";
import type { TenantRole } from "@signet/db";
import type { Context, MiddlewareHandler } from "hono";

/** Answers an admin API refusal. */
function refuse(
  c: Context<SignetEnvironment>,
  code: Parameters<typeof adminErrorBody>[0],
  message: string,
) {
  return c.json(adminErrorBody(code, message), statusForAdminError(code));
}

/**
 * Resolves the presented credential into a principal, or answers 401.
 *
 * A bearer token takes precedence over a cookie. That ordering matters for the
 * console's own development setup, where a browser holding a session may also be
 * used to try a token by hand: the explicit credential should win over the ambient
 * one, so what is being tested is what is being presented.
 *
 * @param context - The server's dependencies.
 */
export function withAdminPrincipal(
  context: ServerContext,
): MiddlewareHandler<SignetEnvironment> {
  return async (c, next) => {
    const presentedToken = bearerToken(c.req.header("authorization"));
    if (presentedToken !== undefined) {
      const authenticated = await findLiveApiToken(
        context.db,
        await hashToken(presentedToken),
        context.clock(),
      );
      if (authenticated === undefined) {
        return refuse(
          c,
          "unauthenticated",
          "That personal access token is not valid",
        );
      }
      // Recorded after the token has been accepted rather than as part of
      // accepting it: the lookup runs on every request, and turning it into a
      // write would serialise concurrent callers holding the same token.
      await touchApiToken(context.db, authenticated.token.id, context.clock());
      c.set("principal", {
        kind: "api-token",
        token: authenticated.token,
        scope: authenticated.scope,
        role: authenticated.role,
      });
      await next();
      return;
    }

    const cookie = readCookie(c.req.header("cookie"), SESSION_COOKIE_NAME);
    if (cookie === undefined) {
      return refuse(c, "unauthenticated", "Sign in to use the admin API");
    }

    const sessionTokenHash = await hashToken(cookie);
    const session = await findLiveAdminSession(
      context.db,
      sessionTokenHash,
      context.clock(),
    );
    if (session === undefined) {
      return refuse(c, "unauthenticated", "That session has expired");
    }

    c.set("principal", {
      kind: "admin-user",
      user: session.user,
      sessionTokenHash,
    });
    await next();
    return;
  };
}

/**
 * Resolves the tenant scope for the principal, or answers 404.
 *
 * The two principal kinds reach a scope by different routes, and neither can
 * reach one they were not given. A person's scope comes from a membership join, so
 * a tenant with no `tenant_members` row for them is invisible. A token's scope is
 * the tenant the token names, and the path is checked against it — presenting a
 * token for one tenant on another tenant's URL is refused rather than silently
 * acting on the token's own tenant, which would make a mistyped script quietly
 * modify the wrong deployment.
 *
 * @param context - The server's dependencies.
 */
export function withAdminTenant(
  context: ServerContext,
): MiddlewareHandler<SignetEnvironment> {
  return async (c, next) => {
    const principal: AdminPrincipal = c.get("principal");
    const tenantSlug = c.req.param("tenantSlug") ?? "";

    if (principal.kind === "api-token") {
      if (principal.scope.tenantSlug !== tenantSlug) {
        return refuse(c, "not_found", "No such tenant");
      }
      c.set("tenant", { scope: principal.scope, role: principal.role });
      await next();
      return;
    }

    const member = await resolveTenantScopeForMember(
      context.db,
      tenantSlug,
      principal.user.id,
    );
    if (member === undefined) {
      return refuse(c, "not_found", "No such tenant");
    }

    c.set("tenant", member);
    await next();
    return;
  };
}

/**
 * Narrows the tenant scope to `/endpoints/:endpointSlug`, or answers 404.
 *
 * The issuer is derived here, from the same configured public URL the OAuth routes
 * are mounted under, so that what the console shows an operator to paste into their
 * FHIR server is the string the server actually serves.
 *
 * @param context - The server's dependencies.
 */
export function withAdminEndpoint(
  context: ServerContext,
): MiddlewareHandler<SignetEnvironment> {
  return async (c, next) => {
    const { scope } = c.get("tenant");
    const endpointSlug = c.req.param("endpointSlug") ?? "";

    const endpoint = await getEndpointBySlug(context.db, scope, endpointSlug);
    if (endpoint === undefined) {
      return refuse(c, "not_found", "No such endpoint");
    }

    const issuer = issuerFor(
      context.config.publicUrl,
      scope.tenantSlug,
      endpoint.slug,
    );
    c.set("endpoint", {
      endpoint,
      scope: endpointScopeFromRow(scope, endpoint),
      issuer,
      urls: endpointUrls(issuer),
    });

    await next();
    return;
  };
}

/**
 * Refuses the request unless the caller holds at least `minimum`.
 *
 * The comparison is `@signet/db`'s, which is a total order over the four roles
 * rather than a set of equality checks — see its documentation for why authority is
 * a comparison here.
 *
 * @param minimum - The least authority the operation accepts.
 */
export function requireRole(
  minimum: TenantRole,
): MiddlewareHandler<SignetEnvironment> {
  return async (c, next) => {
    const { role } = c.get("tenant");
    if (!roleAtLeast(role, minimum)) {
      return refuse(
        c,
        "forbidden",
        `This operation requires the ${minimum} role; you hold ${role}`,
      );
    }
    await next();
    return;
  };
}
