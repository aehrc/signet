/**
 * The admin API's routing table.
 *
 * Authentication is deny-by-default. A single gate runs before every route under
 * `/api/v1`, and the handful of routes that must answer before anybody is signed in
 * are named in `UNAUTHENTICATED_REQUESTS` - an allowlist, so adding a route
 * makes it authenticated without anybody remembering to say so. The alternative,
 * attaching the middleware per route, fails silently in the direction that matters.
 *
 * Tenant resolution and role checks are mounted per path group rather than per
 * handler, because they follow the resource hierarchy: everything below
 * `/tenants/:tenantSlug` needs a scope, and everything below `/endpoints/:slug`
 * needs it narrowed. A handler therefore cannot be reached without the capability it
 * needs to query anything, which is the same argument the OAuth router makes for
 * `withIssuer`.
 *
 * No CORS. The console is served from the same origin as the API, and the responses
 * here are session-authenticated: a cross-origin caller that could read them would
 * be reading a tenant's configuration with the operator's own cookie.
 *
 * Author: John Grimes
 */

import { POLICY_PRESETS } from "@signet/core";
import { Hono } from "hono";

import { registerAuditRoutes } from "./auditRoutes.js";
import {
  withAdminEndpoint,
  withAdminPrincipal,
  withAdminTenant,
} from "./authentication.js";
import { registerClientRoutes } from "./clientRoutes.js";
import { registerEndpointRoutes } from "./endpointRoutes.js";
import { registerEndUserRoutes } from "./endUserRoutes.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { registerFederationRoutes } from "./federationRoutes.js";
import { registerLaunchRoutes } from "./launchRoutes.js";
import { ADMIN_BASE_PATH, ENDPOINT_PATH, TENANT_PATH } from "./paths.js";
import { registerPolicyRoutes } from "./policyRoutes.js";
import {
  adminLoginHandler,
  adminLogoutHandler,
  adminSessionHandler,
} from "./session.js";
import { registerTenantRoutes } from "./tenantRoutes.js";
import { rateLimit } from "../http/rateLimit.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { MiddlewareHandler } from "hono";

/**
 * Requests that are answered without a credential.
 *
 * Exactly one: signing in. Anything added here is a decision to publish part of the
 * admin API, which should be visible in a diff and hard to do by accident.
 *
 * Compared against the whole request path rather than the matched route pattern,
 * because a pattern is only known once a route has matched - and this gate runs
 * before that. Every entry is therefore a literal path with no parameters in it, so
 * there is nothing a caller can put in a path segment to make their request look
 * like one of these.
 */
const UNAUTHENTICATED_REQUESTS: ReadonlySet<string> = new Set([
  `POST ${ADMIN_BASE_PATH}/session`,
]);

/**
 * The authentication gate.
 *
 * @param context - The server's dependencies.
 */
function authenticationGate(
  context: ServerContext,
): MiddlewareHandler<SignetEnvironment> {
  const authenticate = withAdminPrincipal(context);
  return async (c, next) => {
    if (UNAUTHENTICATED_REQUESTS.has(`${c.req.method} ${c.req.path}`)) {
      await next();
      return;
    }
    return await authenticate(c, next);
  };
}

/**
 * Builds the router for `/api/v1/*`.
 *
 * @param context - The server's dependencies.
 */
export function createAdminRouter(
  context: ServerContext,
): Hono<SignetEnvironment> {
  const router = new Hono<SignetEnvironment>();

  router.use("*", authenticationGate(context));
  router.use(`${TENANT_PATH}/*`, withAdminTenant(context));
  router.use(TENANT_PATH, withAdminTenant(context));
  router.use(`${ENDPOINT_PATH}/*`, withAdminEndpoint(context));
  router.use(ENDPOINT_PATH, withAdminEndpoint(context));

  // Session. Signing in is limited by client address for the same reason the
  // end-user surfaces are: it is the one admin route that checks a password.
  // Attached to the POST alone, so signing out is never refused for it.
  router.post(
    "/session",
    rateLimit("signIn", context.clock, context.rateLimits),
    adminLoginHandler(context),
  );
  router.get("/session", adminSessionHandler(context));
  router.delete("/session", adminLogoutHandler(context));

  /**
   * The policy starting points an operator may adopt.
   *
   * Served from `@signet/core` rather than from the database: a preset is code
   * that ships with the deployment, and one stored per tenant would drift from the
   * evaluator it was written against.
   */
  router.get("/presets", (c) =>
    c.json({
      presets: POLICY_PRESETS.map((preset) => ({
        id: preset.id,
        name: preset.name,
        description: preset.description,
        policy: preset.policy,
        references: preset.references,
      })),
    }),
  );

  // Resources, in the order they nest. Each module registers its own routes
  // against the patterns in `./paths.js`, so this reads as a table of contents
  // rather than as a route table nobody can hold in their head.
  registerEndpointRoutes(router, context);
  registerFederationRoutes(router, context);
  registerClientRoutes(router, context);
  registerPolicyRoutes(router, context);
  registerEndUserRoutes(router, context);
  registerLaunchRoutes(router, context);
  registerAuditRoutes(router, context);
  // Last of the resource modules, because it registers `GET /tenants/:tenantSlug`
  // and Hono matches in registration order: a more specific path below the tenant
  // must be registered before the tenant itself.
  registerTenantRoutes(router, context);

  // Registered last, so it answers only what nothing above matched. A `notFound`
  // handler would not do: this router is mounted into the application, and the
  // application's own handler is what runs for an unmatched path - which would
  // answer an admin API call with the SPA's fallback or with plain text.
  router.all("*", (c) =>
    c.json(
      adminErrorBody("not_found", "No such admin API route"),
      statusForAdminError("not_found"),
    ),
  );

  return router;
}

export { ADMIN_BASE_PATH } from "./paths.js";
