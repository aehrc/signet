/**
 * The dependencies every handler needs, assembled once at startup.
 *
 * Passing this explicitly rather than reaching for module-level singletons is
 * what makes the integration tests able to drive the real app: a test builds a
 * context over a throwaway database and a fixed clock, and the handlers cannot
 * tell the difference. There is no ambient `db` for a handler to accidentally
 * use instead.
 *
 * Author: John Grimes
 */

import type { AdminPrincipal } from "./admin/principal.js";
import type { SignetConfig } from "./config.js";
import type { RateLimitStore } from "./http/rateLimit.js";
import type { RemoteJwksCache } from "./oauth/remoteJwks.js";
import type { EndpointUrls } from "@signet/core";
import type {
  AuditRecorder,
  Database,
  Endpoint,
  EndpointScope,
  MemberTenantScope,
  Tenant,
} from "@signet/db";

/**
 * The source of "now".
 *
 * A function rather than a value, because a request's handlers span several
 * awaits and each needs the current instant, not the instant the context was
 * built. Tests substitute a fixed clock; production passes `() => new Date()`.
 *
 * Note that this is the *process* clock, and the repositories deliberately
 * compare expiry against the *database* clock inside SQL. This is for stamping
 * token claims and audit events, not for deciding whether a credential is still
 * live.
 */
export type Clock = () => Date;

/** Everything a request handler may depend on. */
export interface ServerContext {
  readonly config: SignetConfig;
  readonly db: Database;
  readonly audit: AuditRecorder;
  readonly clock: Clock;
  /**
   * The rate-limit counters this application uses.
   *
   * On the context rather than in a module-level variable, so an application is a
   * value rather than something that shares mutable state with every other one in
   * the process. That matters most in the tests, where two stacks in one process
   * must not exhaust each other's allowance.
   */
  readonly rateLimits: RateLimitStore;
  /**
   * The trust anchors' published keys this application has already fetched.
   *
   * On the context for the same reason the rate-limit counters are: an application
   * is a value, and two applications in one test process must not share the
   * mutable state that decides whether an outbound request happens. See
   * `./oauth/remoteJwks.ts` for how long an entry may be reused, which is the part
   * that bounds how long a withdrawn key keeps verifying.
   */
  readonly jwksCache: RemoteJwksCache;
}

/**
 * An endpoint resolved from the request path, with everything derived from it.
 *
 * The scope is the capability that lets a handler query anything tenant-owned;
 * see `@signet/db`'s repository documentation. `issuer` is the exact string
 * published in discovery and minted into `iss`, so it is computed once here
 * rather than being rebuilt per handler.
 */
export interface ResolvedIssuerContext {
  readonly issuer: string;
  readonly urls: EndpointUrls;
  readonly scope: EndpointScope;
  readonly tenant: Tenant;
  readonly endpoint: Endpoint;
}

/**
 * An endpoint resolved from an admin API path.
 *
 * Distinct from {@link ResolvedIssuerContext} because it is reached differently:
 * an OAuth request names an endpoint by its public issuer path and is
 * authenticated by client credentials, whereas an admin request names it inside a
 * tenant the caller has already proved membership of. The tenant row is therefore
 * absent - the tenant scope already carries its slug - and the endpoint row is
 * present because every console view renders its configuration.
 */
export interface AdminEndpointContext {
  readonly endpoint: Endpoint;
  readonly scope: EndpointScope;
  /** The issuer this endpoint publishes, derived from the public URL. */
  readonly issuer: string;
  readonly urls: EndpointUrls;
}

/**
 * Hono's per-request variable map.
 *
 * Declared once so `c.get("issuer")` is typed at every call site instead of
 * being widened to `any` by an untyped Hono generic.
 */
export interface SignetVariables {
  /** Set by the issuer middleware for every route under an endpoint's issuer. */
  readonly issuer: ResolvedIssuerContext;
  /** Set by the admin API's authentication middleware. */
  readonly principal: AdminPrincipal;
  /** The tenant an admin request acts on, and the authority held in it. */
  readonly tenant: MemberTenantScope;
  /** Set for admin routes below `/endpoints/:endpointSlug`. */
  readonly endpoint: AdminEndpointContext;
}

/** Hono's generic parameter for a Signet app or router. */
export interface SignetEnvironment {
  readonly Variables: SignetVariables;
}
