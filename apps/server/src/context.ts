/**
 * The dependencies every handler needs, assembled once at startup.
 *
 * Passing this explicitly rather than reaching for module-level singletons is
 * what makes the integration tests able to drive the real app: a test builds a
 * context over a throwaway database and a fixed clock, and the handlers cannot
 * tell the difference. There is no ambient `db` for a handler to accidentally
 * use instead.
 */

import type { SignetConfig } from "./config.js";
import type { EndpointUrls } from "@signet/core";
import type {
  AuditRecorder,
  Database,
  Endpoint,
  EndpointScope,
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
 * Hono's per-request variable map.
 *
 * Declared once so `c.get("issuer")` is typed at every call site instead of
 * being widened to `any` by an untyped Hono generic.
 */
export interface SignetVariables {
  /** Set by the issuer middleware for every route under an endpoint's issuer. */
  readonly issuer: ResolvedIssuerContext;
}

/** Hono's generic parameter for a Signet app or router. */
export interface SignetEnvironment {
  readonly Variables: SignetVariables;
}
