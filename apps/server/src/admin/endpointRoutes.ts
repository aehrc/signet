/**
 * Endpoints and their signing keys.
 *
 * Creating an endpoint does three things, and it matters that it does all three:
 * it writes the row, generates a signing key and promotes it, and publishes a
 * starting policy. An endpoint missing any one of those exists but cannot issue a
 * token — the token endpoint answers `server_error` for a missing key or a missing
 * policy, deliberately, because both are misconfigurations rather than client
 * mistakes — and an operator who created an endpoint through the console and found
 * it non-functional would reasonably call that a bug.
 *
 * Key rotation is exposed as the three states the data layer models rather than as a
 * single "rotate" button. `next` is published in the JWKS before it signs anything,
 * so relying parties have cached it by the time the first token needs it; promotion
 * makes it active; retirement is separate again, and should wait until the tokens the
 * old key signed have expired. Collapsing those into one action is how a rotation
 * breaks every client that caches a JWKS for five minutes.
 */

import {
  endpointCreateSchema,
  endpointKeyCreateSchema,
  endpointPatchSchema,
} from "@signet/contracts";
import { SMART_BASELINE_PRESET } from "@signet/core";
import {
  createEndpoint,
  createPolicyVersion,
  deleteEndpoint,
  endpointScopeFromRow,
  insertEndpointKey,
  isUniqueViolation,
  listEndpointKeys,
  listEndpoints,
  promoteNextEndpointKey,
  publishPolicy,
  retireEndpointKey,
  updateEndpoint,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH, TENANT_PATH } from "./paths.js";
import { principalAdminUserId } from "./principal.js";
import { parseBody } from "./requestBody.js";
import { endpointKeyView, endpointView } from "./views.js";
import { generateEndpointKey } from "../keys/material.js";
import { issuerFor } from "../oauth/issuer.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Hono } from "hono";

/**
 * Flattens the capability object the API accepts into the columns it maps to.
 *
 * The API nests capabilities under one key when reading and accepts them flat when
 * writing, because a patch naming one flag should not have to restate the other
 * twenty-one. This is the one place the two shapes meet.
 *
 * @param body - A validated create or patch body.
 */
function capabilityColumns(
  body: Readonly<Record<string, unknown>>,
): Record<string, boolean> {
  const columns: Record<string, boolean> = {};
  for (const [name, value] of Object.entries(body)) {
    if (typeof value === "boolean" && name.startsWith("supports")) {
      columns[name] = value;
    }
    if (typeof value === "boolean" && name.startsWith("allows")) {
      columns[name] = value;
    }
  }
  return columns;
}

/** The non-capability columns a create or patch may set. */
const SETTING_FIELDS = [
  "name",
  "description",
  "fhirBaseUrl",
  "scopesSupported",
  "userAccessBrandBundle",
  "userAccessBrandIdentifier",
  "accessTokenTtl",
  "refreshTokenTtl",
  "authMode",
  "consentMode",
  "isProduction",
  "status",
] as const;

/** Picks the settings a body supplied, leaving the rest to the column defaults. */
function settingColumns(
  body: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return Object.fromEntries(
    SETTING_FIELDS.filter((field) => body[field] !== undefined).map((field) => [
      field,
      body[field],
    ]),
  );
}

/**
 * Registers the endpoint and signing key routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerEndpointRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Lists the tenant's endpoints. */
  router.get(`${TENANT_PATH}/endpoints`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("tenant");
    const endpoints = await listEndpoints(context.db, scope);
    return c.json({
      endpoints: endpoints.map((endpoint) =>
        endpointView(
          endpoint,
          issuerFor(context.config.publicUrl, scope.tenantSlug, endpoint.slug),
        ),
      ),
    });
  });

  /**
   * Creates an endpoint, ready to serve.
   *
   * The key and the policy are created in the same request rather than being left
   * for the operator to remember. See the module header.
   */
  router.post(`${TENANT_PATH}/endpoints`, requireRole("admin"), async (c) => {
    const { scope } = c.get("tenant");
    const body = await parseBody(c, endpointCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    let endpoint;
    try {
      endpoint = await createEndpoint(context.db, scope, {
        slug: body.slug,
        name: body.name,
        fhirBaseUrl: body.fhirBaseUrl,
        ...settingColumns(body),
        ...capabilityColumns(body),
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        return c.json(
          adminErrorBody(
            "conflict",
            "This tenant already has an endpoint with that slug",
          ),
          statusForAdminError("conflict"),
        );
      }
      throw error;
    }

    const endpointScope = endpointScopeFromRow(scope, endpoint);

    const key = await generateEndpointKey("ES384", context.config.masterKey);
    await insertEndpointKey(context.db, endpointScope, {
      kid: key.kid,
      algorithm: key.algorithm,
      publicJwk: key.publicJwk,
      privateJwkEncrypted: key.privateJwkEncrypted,
      status: "next",
    });
    // Inserted as `next` and promoted, rather than inserted as `active`: promotion
    // is what stamps `activated_at`, which is how the signing key is chosen.
    const promotion = await promoteNextEndpointKey(context.db, endpointScope);
    if (!promotion.ok) {
      throw new Error(
        `could not activate the new endpoint's signing key: ${promotion.reason}`,
      );
    }

    const version = await createPolicyVersion(context.db, endpointScope, {
      document: SMART_BASELINE_PRESET,
      createdBy: principalAdminUserId(c.get("principal")),
      note: "SMART baseline, created with the endpoint",
    });
    if (!version.ok) {
      throw new Error(`could not create a policy version: ${version.reason}`);
    }
    const published = await publishPolicy(
      context.db,
      endpointScope,
      version.policy.version,
    );
    if (!published.ok) {
      throw new Error(`could not publish the policy: ${published.reason}`);
    }

    const issuer = issuerFor(
      context.config.publicUrl,
      scope.tenantSlug,
      endpoint.slug,
    );

    await recordAdminEvent(context, c, {
      action: "endpoint.created",
      target: { type: "endpoint", id: endpoint.id },
      detail: {
        slug: endpoint.slug,
        fhirBaseUrl: endpoint.fhirBaseUrl,
        kid: key.kid,
      },
    });

    return c.json({ endpoint: endpointView(endpoint, issuer) }, 201);
  });

  /** Reads one endpoint. */
  router.get(ENDPOINT_PATH, requireRole("viewer"), (c) => {
    const { endpoint, issuer } = c.get("endpoint");
    return c.json({ endpoint: endpointView(endpoint, issuer) });
  });

  /**
   * Edits an endpoint.
   *
   * Every capability flag is a conformance claim published in the discovery
   * document, so a change here changes what Signet promises. The audit event names
   * the fields that changed for exactly that reason.
   */
  router.patch(ENDPOINT_PATH, requireRole("admin"), async (c) => {
    const { scope, endpoint, issuer } = c.get("endpoint");
    const body = await parseBody(c, endpointPatchSchema);
    if (body instanceof Response) {
      return body;
    }

    const patch = {
      ...settingColumns(body),
      ...capabilityColumns(body),
    };
    if (Object.keys(patch).length === 0) {
      return c.json({ endpoint: endpointView(endpoint, issuer) });
    }

    const updated = await updateEndpoint(
      context.db,
      scope,
      patch,
      context.clock(),
    );
    if (updated === undefined) {
      return c.json(
        adminErrorBody("not_found", "No such endpoint"),
        statusForAdminError("not_found"),
      );
    }

    await recordAdminEvent(context, c, {
      action: "endpoint.updated",
      target: { type: "endpoint", id: endpoint.id },
      detail: { fields: Object.keys(patch) },
    });

    return c.json({ endpoint: endpointView(updated, issuer) });
  });

  /**
   * Deletes an endpoint and everything configured under it.
   *
   * Cascades to keys, clients, policies, users and every runtime row. The audit
   * events survive, with `endpoint_id` nulled and the slug retained in their detail,
   * because deleting one endpoint must not erase the tenant's record of what
   * happened on it.
   */
  router.delete(ENDPOINT_PATH, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");

    // Recorded before the delete: afterwards the endpoint row is gone, and an event
    // naming a deleted endpoint would have its foreign key nulled on the way in.
    await recordAdminEvent(context, c, {
      action: "endpoint.deleted",
      target: { type: "endpoint", id: endpoint.id },
      detail: { slug: endpoint.slug },
    });

    const deleted = await deleteEndpoint(context.db, scope);
    if (!deleted) {
      return c.json(
        adminErrorBody("not_found", "No such endpoint"),
        statusForAdminError("not_found"),
      );
    }
    return c.body(null, 204);
  });

  /** Lists the endpoint's signing keys, newest first. */
  router.get(`${ENDPOINT_PATH}/keys`, requireRole("admin"), async (c) => {
    const { scope } = c.get("endpoint");
    const keys = await listEndpointKeys(context.db, scope);
    return c.json({ keys: keys.map(endpointKeyView) });
  });

  /**
   * Generates the next signing key.
   *
   * Created as `next`, published in the JWKS immediately and signing nothing yet.
   * The delay between this and promotion is what lets relying parties cache the key
   * before the first token needs it.
   */
  router.post(`${ENDPOINT_PATH}/keys`, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const body = await parseBody(c, endpointKeyCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    const generated = await generateEndpointKey(
      body.algorithm,
      context.config.masterKey,
    );
    let key;
    try {
      key = await insertEndpointKey(context.db, scope, {
        kid: generated.kid,
        algorithm: generated.algorithm,
        publicJwk: generated.publicJwk,
        privateJwkEncrypted: generated.privateJwkEncrypted,
        status: "next",
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        // `kid` is the key's own thumbprint, so a collision means this exact key is
        // already published — which is a different statement from bad luck.
        return c.json(
          adminErrorBody("conflict", "That key is already published"),
          statusForAdminError("conflict"),
        );
      }
      throw error;
    }

    await recordAdminEvent(context, c, {
      action: "key.created",
      target: { type: "endpoint-key", id: key.id },
      detail: {
        kid: key.kid,
        algorithm: key.algorithm,
        endpointSlug: endpoint.slug,
      },
    });

    return c.json({ key: endpointKeyView(key) }, 201);
  });

  /**
   * Promotes the `next` key to `active`, retiring the one it replaces.
   *
   * Refused when there is no `next` key, rather than generating one: an operator who
   * has not published the replacement yet is a few minutes early, and rotating to a
   * key nobody has cached would reject the first tokens it signed.
   */
  router.post(
    `${ENDPOINT_PATH}/keys/promote`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");

      const promotion = await promoteNextEndpointKey(context.db, scope);
      if (!promotion.ok) {
        // The only refusal the data layer has: there is nothing queued. Rotating
        // to nothing would leave the endpoint unable to sign at all.
        return c.json(
          adminErrorBody(
            "conflict",
            "There is no next key to promote. Generate one first, and give relying parties time to cache it.",
          ),
          statusForAdminError("conflict"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "key.rotated",
        target: { type: "endpoint-key", id: promotion.activated.id },
        detail: {
          kid: promotion.activated.kid,
          endpointSlug: endpoint.slug,
        },
      });

      return c.json({ key: endpointKeyView(promotion.activated) });
    },
  );

  /**
   * Retires a key.
   *
   * A retired key stops signing and stops being published, so any token it signed
   * becomes unverifiable. The console warns; the API allows it, because a key
   * believed to be compromised must be withdrawable immediately.
   */
  router.post(
    `${ENDPOINT_PATH}/keys/:kid/retire`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const kid = c.req.param("kid");

      const retired = await retireEndpointKey(
        context.db,
        scope,
        kid,
        context.clock(),
      );
      if (retired === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such key on this endpoint"),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "key.retired",
        target: { type: "endpoint-key", id: retired.id },
        detail: { kid, endpointSlug: endpoint.slug },
      });

      return c.json({ key: endpointKeyView(retired) });
    },
  );
}

/** Re-exported so the tests can name the capability shape they send. */

export { type EndpointCapabilities } from "@signet/contracts";
