/**
 * Configuring the two issuers an endpoint may trust.
 *
 * A trust anchor's software statements register clients here; a ticket issuer's
 * permission tickets are exchanged for tokens here. They are different
 * capabilities, but they are configured identically - read the rule, save it,
 * remove it, fetch the keys and report what came back - so they are registered
 * from one description each rather than from two copies of four handlers.
 *
 * One thing to keep straight, and it is the same for both: the rule *is* the
 * capability. There is no separate switch, no `enabled` column and nothing to
 * leave half-configured - saving a rule turns the capability on and deleting it
 * turns it off. An endpoint with no anchor answers 404 at `/register` and
 * advertises nothing; an endpoint with no ticket issuer refuses the exchange grant
 * and advertises no ticket types. Modelling either as a rule plus a flag would
 * create a fourth state nobody wants: a configured issuer that is not in force, or
 * a flag in force with no issuer.
 *
 * The write is an upsert, as the identity provider's is and for the same reason:
 * the table's primary key is the endpoint, so "configure this endpoint's issuer"
 * is one operation whether or not one was there before, and asking an operator to
 * know which is asking them to model our schema.
 *
 * The check route is the one that earns its place. An issuer that is wrong fails
 * at the moment an app tries to use it, where the app developer sees a refusal and
 * the operator sees nothing - so an operator can ask Signet to fetch the published
 * keys and report exactly what it found, before anybody tries. It reads the stored
 * address rather than one from the body, which keeps it from being a
 * general-purpose fetcher for anybody who reaches the admin API; the outbound guard
 * applies either way.
 *
 * Author: John Grimes
 */

import {
  ticketIssuerWriteSchema,
  trustAnchorWriteSchema,
} from "@signet/contracts";
import {
  deleteEndpointTicketIssuer,
  deleteEndpointTrustAnchor,
  getEndpointTicketIssuer,
  getEndpointTrustAnchor,
  upsertEndpointTicketIssuer,
  upsertEndpointTrustAnchor,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { resolveRemoteJwks } from "../oauth/remoteJwks.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { EndpointUrls } from "@signet/core";
import type {
  AuditAction,
  AuditTargetType,
  EndpointTicketIssuer,
  EndpointTrustAnchor,
} from "@signet/db";
import type { Hono } from "hono";
import type { ZodType } from "zod";

/** The transaction-bound endpoint scope every repository here demands. */
type BoundEndpoint = Parameters<typeof getEndpointTrustAnchor>[0];

/** Everything that distinguishes one trust rule's routes from the other's. */
interface TrustRuleSpec<TRule, TInput> {
  /** The path segment under the endpoint, e.g. `anchor`. */
  readonly segment: string;
  /** The field the rule is returned and accepted under, e.g. `anchor`. */
  readonly field: string;
  /** What to call the rule when there is none, e.g. `trust anchor`. */
  readonly noun: string;
  readonly schema: ZodType<TInput>;
  readonly read: (scope: BoundEndpoint) => Promise<TRule | undefined>;
  readonly upsert: (
    scope: BoundEndpoint,
    input: TInput,
    now: Date,
  ) => Promise<TRule>;
  readonly remove: (scope: BoundEndpoint) => Promise<boolean>;
  /** The rule as the console sees it. */
  readonly view: (rule: TRule, urls: EndpointUrls) => Record<string, unknown>;
  /** Where the rule publishes its keys, for the check route. */
  readonly jwksUriOf: (rule: TRule) => string;
  /** What the audit trail records when the rule is saved. Never key material. */
  readonly detailOf: (rule: TRule) => Record<string, unknown>;
  readonly configuredAction: AuditAction;
  readonly removedAction: AuditAction;
  readonly targetType: AuditTargetType;
}

/** The trust anchor rule as the console sees it. */
function trustAnchorView(
  anchor: EndpointTrustAnchor,
  urls: EndpointUrls,
): Record<string, unknown> {
  return {
    issuer: anchor.issuer,
    jwksUri: anchor.jwksUri,
    maxVouchingDays: anchor.maxVouchingDays,
    updatedAt: anchor.updatedAt,
    /**
     * Echoed back because an operator has to give it to the anchor, and deriving
     * it by hand from the issuer is exactly the transcription that goes wrong.
     */
    registrationEndpoint: urls.registration,
  };
}

/** The ticket issuer rule as the console sees it. */
function ticketIssuerView(
  rule: EndpointTicketIssuer,
  urls: EndpointUrls,
): Record<string, unknown> {
  return {
    issuer: rule.issuer,
    jwksUri: rule.jwksUri,
    acceptedTicketTypes: rule.acceptedTicketTypes,
    maxTokenLifetimeSecs: rule.maxTokenLifetimeSecs,
    updatedAt: rule.updatedAt,
    // The address a ticket is presented at, for the same reason the anchor's
    // registration endpoint is echoed back.
    tokenEndpoint: urls.token,
  };
}

/** Registers the four routes one trust rule needs. */
function registerRuleRoutes<TRule, TInput>(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
  spec: TrustRuleSpec<TRule, TInput>,
): void {
  const path = `${ENDPOINT_PATH}/trust/${spec.segment}`;

  /** Reads the endpoint's rule, or null when it has none. */
  router.get(path, requireRole("admin"), async (c) => {
    const { scope, urls } = c.get("endpoint");
    const rule = await withTenantScope(context.db, scope, (bound) =>
      spec.read(bound),
    );
    // Null rather than a 404: an endpoint with no rule is the normal case, and
    // answering 404 would have every caller unpicking a failure that is not one.
    return c.json({
      [spec.field]: rule === undefined ? null : spec.view(rule, urls),
    });
  });

  /** Sets the endpoint's rule, turning the capability on. */
  router.put(path, requireRole("admin"), async (c) => {
    const { scope, endpoint, urls } = c.get("endpoint");
    const body = await parseBody(c, spec.schema);
    if (body instanceof Response) {
      return body;
    }

    const rule = await withTenantScope(context.db, scope, (bound) =>
      spec.upsert(bound, body, context.clock()),
    );

    await recordAdminEvent(context, c, {
      action: spec.configuredAction,
      target: { type: spec.targetType, id: endpoint.id },
      detail: spec.detailOf(rule),
    });

    return c.json({ [spec.field]: spec.view(rule, urls) });
  });

  /** Removes the rule, returning the endpoint to refusing. */
  router.delete(path, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const removed = await withTenantScope(context.db, scope, (bound) =>
      spec.remove(bound),
    );
    if (!removed) {
      return c.json(
        adminErrorBody("not_found", `This endpoint has no ${spec.noun}`),
        statusForAdminError("not_found"),
      );
    }

    await recordAdminEvent(context, c, {
      action: spec.removedAction,
      target: { type: spec.targetType, id: endpoint.id },
    });
    return c.body(null, 204);
  });

  /**
   * Fetches the issuer's published keys and reports what came back.
   *
   * Through the same resolver the OAuth surfaces use, cache included, so what an
   * operator is shown is what the next registration or exchange will verify
   * against rather than a second opinion that could differ from it.
   */
  router.post(`${path}/check`, requireRole("admin"), async (c) => {
    const { scope } = c.get("endpoint");
    const rule = await withTenantScope(context.db, scope, (bound) =>
      spec.read(bound),
    );
    if (rule === undefined) {
      return c.json(
        adminErrorBody("not_found", `This endpoint has no ${spec.noun}`),
        statusForAdminError("not_found"),
      );
    }

    const fetchedAt = context.clock();
    const resolved = await resolveRemoteJwks({
      jwksUri: spec.jwksUriOf(rule),
      cache: context.jwksCache,
      now: fetchedAt,
      allowPrivateAddresses: context.config.allowPrivateOutboundFetches,
    });
    if (!resolved.ok) {
      return c.json({
        ok: false,
        problem: resolved.reason,
        description: resolved.description,
      });
    }

    return c.json({
      ok: true,
      fetchedAt: fetchedAt.toISOString(),
      // Identifiers only. These are public keys and the document is public, but
      // there is no reason for the console to hold key material it will never
      // use, and a screenful of JWKs tells an operator nothing.
      keyIds: resolved.keys.keys.map((key) => key.kid ?? "(no kid)"),
    });
  });
}

/**
 * Registers the trust rule routes for both the anchor and the ticket issuer.
 *
 * @param router - The admin router.
 * @param context - The server's dependencies.
 * @example
 * ```ts
 * registerTrustRoutes(router, context);
 * ```
 */
export function registerTrustRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  registerRuleRoutes(router, context, {
    segment: "anchor",
    field: "anchor",
    noun: "trust anchor",
    schema: trustAnchorWriteSchema,
    read: getEndpointTrustAnchor,
    upsert: upsertEndpointTrustAnchor,
    remove: deleteEndpointTrustAnchor,
    view: trustAnchorView,
    jwksUriOf: (anchor) => anchor.jwksUri,
    detailOf: (anchor) => ({
      issuer: anchor.issuer,
      jwksUri: anchor.jwksUri,
      maxVouchingDays: anchor.maxVouchingDays,
    }),
    configuredAction: "trust-anchor.configured",
    removedAction: "trust-anchor.removed",
    targetType: "trust-anchor",
  });

  registerRuleRoutes(router, context, {
    segment: "ticket-issuer",
    field: "ticketIssuer",
    noun: "permission ticket issuer",
    schema: ticketIssuerWriteSchema,
    read: getEndpointTicketIssuer,
    upsert: upsertEndpointTicketIssuer,
    remove: deleteEndpointTicketIssuer,
    view: ticketIssuerView,
    jwksUriOf: (rule) => rule.jwksUri,
    detailOf: (rule) => ({
      issuer: rule.issuer,
      jwksUri: rule.jwksUri,
      acceptedTicketTypes: rule.acceptedTicketTypes,
      maxTokenLifetimeSecs: rule.maxTokenLifetimeSecs,
    }),
    configuredAction: "ticket-issuer.configured",
    removedAction: "ticket-issuer.removed",
    targetType: "ticket-issuer",
  });
}
