/**
 * Configuring the trust anchor an endpoint accepts registrations from.
 *
 * Four routes and one thing to keep straight: the rule *is* the capability. There
 * is no separate switch, no `enabled` column and nothing to leave half-configured
 * - saving a rule turns vouched registration on and deleting it turns it off, and
 * an endpoint with no rule answers 404 at `/register` and advertises nothing.
 * Modelling it as a rule plus a flag would create a fourth state nobody wants: a
 * configured anchor that is not in force, or a flag in force with no anchor.
 *
 * The write is an upsert, as the identity provider's is and for the same reason:
 * the table's primary key is the endpoint, so "configure this endpoint's anchor"
 * is one operation whether or not one was there before, and asking an operator to
 * know which is asking them to model our schema.
 *
 * The check route is the one that earns its place. An anchor that is wrong fails
 * at the moment an app tries to register, where the app developer sees a refusal
 * and the operator sees nothing - so an operator can ask Signet to fetch the
 * anchor's keys and report exactly what it found, before anybody tries. It reads
 * the stored address rather than one from the body, which keeps it from being a
 * general-purpose fetcher for anybody who reaches the admin API; the outbound
 * guard applies either way.
 *
 * Author: John Grimes
 */

import { trustAnchorWriteSchema } from "@signet/contracts";
import {
  deleteEndpointTrustAnchor,
  getEndpointTrustAnchor,
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
import type { EndpointTrustAnchor } from "@signet/db";
import type { Hono } from "hono";

/** The rule as the console sees it. */
function trustAnchorView(
  anchor: EndpointTrustAnchor,
  registrationEndpoint: string,
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
    registrationEndpoint,
  };
}

/**
 * Registers the trust rule routes.
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
  /** Reads the endpoint's trust anchor rule, or null when it has none. */
  router.get(
    `${ENDPOINT_PATH}/trust/anchor`,
    requireRole("admin"),
    async (c) => {
      const { scope, urls } = c.get("endpoint");
      const anchor = await withTenantScope(context.db, scope, (bound) =>
        getEndpointTrustAnchor(bound),
      );
      // Null rather than a 404: an endpoint accepting no registrations is the
      // normal case, and answering 404 would have every caller unpicking a
      // failure that is not one.
      return c.json({
        anchor:
          anchor === undefined
            ? null
            : trustAnchorView(anchor, urls.registration),
      });
    },
  );

  /** Sets the endpoint's trust anchor rule, turning vouched registration on. */
  router.put(
    `${ENDPOINT_PATH}/trust/anchor`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint, urls } = c.get("endpoint");
      const body = await parseBody(c, trustAnchorWriteSchema);
      if (body instanceof Response) {
        return body;
      }

      const anchor = await withTenantScope(context.db, scope, (bound) =>
        upsertEndpointTrustAnchor(bound, body, context.clock()),
      );

      await recordAdminEvent(context, c, {
        action: "trust-anchor.configured",
        target: { type: "trust-anchor", id: endpoint.id },
        detail: {
          issuer: anchor.issuer,
          jwksUri: anchor.jwksUri,
          maxVouchingDays: anchor.maxVouchingDays,
        },
      });

      return c.json({ anchor: trustAnchorView(anchor, urls.registration) });
    },
  );

  /** Removes the rule, returning the endpoint to refusing registration. */
  router.delete(
    `${ENDPOINT_PATH}/trust/anchor`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const removed = await withTenantScope(context.db, scope, (bound) =>
        deleteEndpointTrustAnchor(bound),
      );
      if (!removed) {
        return c.json(
          adminErrorBody("not_found", "This endpoint has no trust anchor"),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "trust-anchor.removed",
        target: { type: "trust-anchor", id: endpoint.id },
      });
      return c.body(null, 204);
    },
  );

  /**
   * Fetches the anchor's published keys and reports what came back.
   *
   * Through the same resolver a registration uses, cache included, so what an
   * operator is shown is what the next registration will verify against rather
   * than a second opinion that could differ from it.
   */
  router.post(
    `${ENDPOINT_PATH}/trust/anchor/check`,
    requireRole("admin"),
    async (c) => {
      const { scope } = c.get("endpoint");
      const anchor = await withTenantScope(context.db, scope, (bound) =>
        getEndpointTrustAnchor(bound),
      );
      if (anchor === undefined) {
        return c.json(
          adminErrorBody("not_found", "This endpoint has no trust anchor"),
          statusForAdminError("not_found"),
        );
      }

      const fetchedAt = context.clock();
      const resolved = await resolveRemoteJwks({
        jwksUri: anchor.jwksUri,
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
    },
  );
}
