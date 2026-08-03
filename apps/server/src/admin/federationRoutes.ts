/**
 * Configuring the upstream identity provider an endpoint federates to.
 *
 * Three routes and one rule: the client secret goes in and never comes back. The
 * view has no field for it, only a flag saying whether one is stored, because a
 * console that displays a secret is a console that puts it in a screenshot, a
 * browser cache and a support ticket.
 *
 * The write is a single upsert rather than a create and an update, because the
 * table's primary key is the endpoint - an endpoint federates to at most one
 * provider, and asking an operator to know whether they are creating or editing is
 * asking them to model our schema.
 *
 * Omitting `clientSecret` leaves the stored one alone. That is what makes it
 * possible to correct a claim mapping without re-entering a credential the person
 * editing may not have; sending an explicit null is how it is cleared.
 *
 * The check route is the one that earns its place. Federation fails in the space
 * between two servers, where neither party's log says anything useful, so an
 * operator can ask Signet to fetch the discovery document and report exactly what
 * it found - before a person is standing at a login page.
 */

import { idpConfigWriteSchema } from "@signet/contracts";
import { validateUpstreamMetadata, supportsPkce } from "@signet/core";
import {
  deleteIdpConfig,
  encryptSecret,
  getIdpConfig,
  upsertIdpConfig,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { parseBody } from "./requestBody.js";
import { federationCallbackUrl } from "../oauth/federation.js";
import { fetchGuardedJson } from "../security/outboundFetch.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { IdpClaimMappings, IdpConfig } from "@signet/db";
import type { Hono } from "hono";

/**
 * The provider configuration as the console sees it.
 *
 * `hasClientSecret` rather than the secret: an operator needs to know whether one
 * is stored, which is a different question from what it is, and only the first has
 * an answer this API will give.
 */
function idpConfigView(
  config: IdpConfig,
  redirectUri: string,
): Record<string, unknown> {
  return {
    issuer: config.issuer,
    displayName: config.displayName,
    clientId: config.clientId,
    hasClientSecret: config.clientSecretEncrypted !== null,
    scopes: config.scopes,
    claimMappings: config.claimMappings,
    discoveryCachedAt: config.discoveryCachedAt,
    updatedAt: config.updatedAt,
    /**
     * Echoed back because the operator has to register it with the provider, and
     * deriving it by hand from the issuer is exactly the kind of transcription
     * that produces an afternoon of `redirect_uri_mismatch`.
     */
    redirectUri,
  };
}

/**
 * Registers the federation routes.
 *
 * @param router - The admin router.
 * @param context - The server's dependencies.
 */
export function registerFederationRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Reads the endpoint's provider configuration. */
  router.get(`${ENDPOINT_PATH}/idp`, requireRole("admin"), async (c) => {
    const { scope, issuer } = c.get("endpoint");
    const config = await getIdpConfig(context.db, scope);
    return c.json({
      idp:
        config === undefined
          ? null
          : idpConfigView(config, federationCallbackUrl(issuer)),
    });
  });

  /** Sets the endpoint's provider configuration. */
  router.put(`${ENDPOINT_PATH}/idp`, requireRole("admin"), async (c) => {
    const { scope, endpoint, issuer } = c.get("endpoint");
    const body = await parseBody(c, idpConfigWriteSchema);
    if (body instanceof Response) {
      return body;
    }

    const existing = await getIdpConfig(context.db, scope);
    const secret = await resolveSecret(context, body.clientSecret, existing);

    const config = await upsertIdpConfig(
      context.db,
      scope,
      {
        issuer: body.issuer,
        displayName: body.displayName ?? null,
        clientId: body.clientId,
        clientSecretEncrypted: secret,
        // `openid` is not negotiable: without it the provider returns no ID token,
        // and an ID token is the only thing in the response Signet can verify.
        scopes: [...withOpenId(body.scopes)],
        claimMappings: claimMappings(body.claimMappings),
        // Cleared on every write, so an issuer change cannot be followed by one
        // more request against the provider that was configured before it.
        discoveryCachedAt: null,
      },
      context.clock(),
    );

    await recordAdminEvent(context, c, {
      action:
        existing === undefined ? "idp-config.created" : "idp-config.updated",
      target: { type: "idp-config", id: endpoint.id },
      detail: {
        issuer: config.issuer,
        clientId: config.clientId,
        hasClientSecret: config.clientSecretEncrypted !== null,
      },
    });

    return c.json({
      idp: idpConfigView(config, federationCallbackUrl(issuer)),
    });
  });

  /** Stops the endpoint federating. */
  router.delete(`${ENDPOINT_PATH}/idp`, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const removed = await deleteIdpConfig(context.db, scope);
    if (!removed) {
      return c.json(
        adminErrorBody("not_found", "This endpoint has no identity provider"),
        statusForAdminError("not_found"),
      );
    }

    await recordAdminEvent(context, c, {
      action: "idp-config.deleted",
      target: { type: "idp-config", id: endpoint.id },
    });
    return c.body(null, 204);
  });

  /**
   * Fetches the provider's discovery document and reports what it says.
   *
   * Reads the stored configuration rather than taking an issuer in the body, so
   * this cannot be used as a general-purpose fetcher for arbitrary URLs by anybody
   * who reaches the admin API - it goes through the SSRF guard either way, but a
   * route that fetches what an operator already configured has a narrower blast
   * radius than one that fetches what a request names.
   */
  router.post(`${ENDPOINT_PATH}/idp/check`, requireRole("admin"), async (c) => {
    const { scope } = c.get("endpoint");
    const config = await getIdpConfig(context.db, scope);
    if (config === undefined) {
      return c.json(
        adminErrorBody("not_found", "This endpoint has no identity provider"),
        statusForAdminError("not_found"),
      );
    }

    const allowPrivate = context.config.allowPrivateOutboundFetches;
    const url = `${config.issuer}/.well-known/openid-configuration`;
    const fetched = await fetchGuardedJson(url, {
      allowPrivateAddresses: allowPrivate,
    });
    if (!fetched.ok) {
      return c.json({
        ok: false,
        problem: fetched.reason,
        description: fetched.description,
      });
    }

    const validated = validateUpstreamMetadata(fetched.value, config.issuer, {
      allowInsecureEndpoints: allowPrivate,
    });
    if (!validated.ok) {
      return c.json({
        ok: false,
        problem: validated.code,
        description: validated.description,
      });
    }

    return c.json({
      ok: true,
      metadata: validated.metadata,
      // Reported rather than enforced: Signet sends a challenge regardless, and an
      // operator should know when the provider says it will be ignored.
      supportsPkce: supportsPkce(validated.metadata),
    });
  });
}

/**
 * Decides what to store in the secret column.
 *
 * Three cases, and the middle one is the reason this is a function: an absent
 * field keeps what is there, an explicit null clears it, and a value replaces it.
 * A patch that silently cleared a credential because a form did not send the field
 * would break federation at the next sign-in and nowhere near the edit that caused
 * it.
 */
async function resolveSecret(
  context: ServerContext,
  supplied: string | null | undefined,
  existing: IdpConfig | undefined,
): Promise<string | null> {
  if (supplied === undefined) {
    return existing?.clientSecretEncrypted ?? null;
  }
  if (supplied === null) {
    return null;
  }
  return await encryptSecret(supplied, context.config.masterKey);
}

/**
 * The claim mapping with unset fields absent rather than undefined.
 *
 * The stored value is JSON, and a key present with the value `undefined` becomes
 * `null` on the way through - which reads later as "the operator mapped this to
 * nothing" rather than "the operator did not map it". Dropping the key keeps those
 * two distinguishable.
 */
function claimMappings(
  mappings:
    | {
        readonly fhirUser?: string | undefined;
        readonly roles?: string | undefined;
        readonly displayName?: string | undefined;
        readonly attributes?: readonly string[] | undefined;
      }
    | undefined,
): IdpClaimMappings {
  if (mappings === undefined) {
    return {};
  }
  return {
    ...(mappings.fhirUser === undefined ? {} : { fhirUser: mappings.fhirUser }),
    ...(mappings.roles === undefined ? {} : { roles: mappings.roles }),
    ...(mappings.displayName === undefined
      ? {}
      : { displayName: mappings.displayName }),
    ...(mappings.attributes === undefined
      ? {}
      : { attributes: mappings.attributes }),
  };
}

/** The requested scopes, with `openid` guaranteed and duplicates dropped. */
function withOpenId(scopes: readonly string[] | undefined): readonly string[] {
  const requested =
    scopes === undefined || scopes.length === 0 ? ["profile"] : scopes;
  return [...new Set(["openid", ...requested])];
}
