/**
 * The launch simulator, and the code an operator needs on the other side.
 *
 * The simulator mints a real launch handle through the same repository the EHR
 * endpoint uses, with the same TTL and the same single-use semantics. That is the
 * point: a launch that works here works from a real EHR, because it *is* the same
 * operation. The only difference is how the caller authenticated - an administrator
 * with a session rather than a client with a credential - and that the handle is
 * always bound to the app that will redeem it, because the console always knows which
 * app it is about to open.
 *
 * The interceptor route generates Java. HAPI FHIR has no claim contract to write a
 * policy preset against - `AuthorizationInterceptor` requires the operator to write
 * `buildRuleList` themselves, and reads no token by itself - so what Signet can
 * usefully ship is the other side of the handshake: the interceptor that consumes what
 * this endpoint was configured to mint. See `@signet/core`'s generator for what the
 * generated code deliberately does not do.
 *
 * Author: John Grimes
 */

import { launchSimulationSchema } from "@signet/contracts";
import { generateHapiInterceptor, toLaunchContext } from "@signet/core";
import {
  createLaunchContext,
  generateOpaqueToken,
  getClientByClientId,
  hashToken,
  isClientUsable,
  listPublishableEndpointKeys,
  clientScopeFromRow,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { LAUNCH_CONTEXT_TTL_SECONDS } from "../oauth/launchContextEndpoint.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Hono } from "hono";

/**
 * Registers the launch simulator and integration snippet routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerLaunchRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /**
   * Mints a launch handle and reports where to open the app.
   *
   * `launchUrl` is assembled here rather than in the console so that the two
   * parameters an EHR launch requires - `iss` and `launch` - are added in one place
   * and cannot be forgotten.
   */
  router.post(
    `${ENDPOINT_PATH}/launch`,
    requireRole("developer"),
    async (c) => {
      const { scope, endpoint, issuer } = c.get("endpoint");

      if (!endpoint.supportsEhrLaunch) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            "This endpoint does not support the EHR launch, so a launch handle would never be redeemable",
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const body = await parseBody(c, launchSimulationSchema);
      if (body instanceof Response) {
        return body;
      }

      const client = await getClientByClientId(
        context.db,
        scope,
        body.clientId,
      );
      if (client === undefined || !isClientUsable(client)) {
        return c.json(
          adminErrorBody("not_found", "No such active client on this endpoint"),
          statusForAdminError("not_found"),
        );
      }

      const handle = generateOpaqueToken();
      const row = await createLaunchContext(context.db, scope, {
        handleHash: await hashToken(handle),
        context: toLaunchContext({
          patient: body.patient,
          encounter: body.encounter,
          intent: body.intent,
          tenant: body.tenant,
          needPatientBanner: body.needPatientBanner,
          smartStyleUrl: body.smartStyleUrl,
        }),
        createdBy: `console:${endpoint.slug}`,
        expiresAt: new Date(
          context.clock().getTime() + LAUNCH_CONTEXT_TTL_SECONDS * 1000,
        ),
        // Always bound. The console knows which app it is launching, and an unbound
        // handle is redeemable by whichever app presents it first.
        boundTo: clientScopeFromRow(scope, client),
      });

      await recordAdminEvent(context, c, {
        action: "launch-context.created",
        target: { type: "launch-context", id: row.id },
        detail: {
          clientId: client.clientId,
          patient: body.patient ?? null,
          encounter: body.encounter ?? null,
          simulated: true,
        },
      });

      const launchUrl =
        client.launchUri === null
          ? null
          : (() => {
              const url = new URL(client.launchUri);
              url.searchParams.set("iss", issuer);
              url.searchParams.set("launch", handle);
              return url.toString();
            })();

      c.header("Cache-Control", "no-store");
      return c.json(
        {
          launch: handle,
          iss: issuer,
          expiresIn: LAUNCH_CONTEXT_TTL_SECONDS,
          /** Null when the client registered no launch URI; there is nowhere to open. */
          launchUrl,
        },
        201,
      );
    },
  );

  /**
   * Generates a HAPI FHIR authorization interceptor for this endpoint.
   *
   * Served as `text/plain` rather than JSON: it is a file an operator saves into a
   * Java project, and a JSON-encoded string would have to be unescaped first.
   */
  router.get(
    `${ENDPOINT_PATH}/integrations/hapi-interceptor`,
    requireRole("viewer"),
    async (c) => {
      const { endpoint, issuer, urls, scope } = c.get("endpoint");

      // The algorithms this endpoint actually publishes keys for, so an operator
      // who chose RS256 for a resource server that reads nothing else is not
      // handed an interceptor that rejects their own tokens.
      const keys = await listPublishableEndpointKeys(context.db, scope);

      const source = generateHapiInterceptor({
        issuer,
        jwksUri: urls.jwks,
        audience: endpoint.fhirBaseUrl,
        endpointName: endpoint.name,
        algorithms: [...new Set(keys.map((key) => key.algorithm))],
      });

      c.header("Content-Type", "text/plain; charset=utf-8");
      c.header(
        "Content-Disposition",
        'attachment; filename="SignetAuthorizationInterceptor.java"',
      );
      return c.body(source);
    },
  );
}
