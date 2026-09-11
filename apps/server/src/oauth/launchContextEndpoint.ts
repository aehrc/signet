/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The launch-context API: how an EHR mints a `launch` handle.
 *
 * This is the piece that makes an EHR launch possible without Signet being the EHR.
 * The EHR - or the console's launch simulator, or a connectathon harness - posts the
 * context it wants an app to receive, and gets back a single-use opaque handle to
 * put in the app's launch URL alongside `iss`. Signet holds the context; the handle
 * carries nothing.
 *
 * Two decisions are worth stating.
 *
 * The caller authenticates as a client, with the same three methods as the token
 * endpoint, and must be registered for `authorization_code` on this endpoint. There
 * is no separate credential type for "the EHR": an EHR that can launch apps is a
 * registered client of the authorization server, and giving it a second kind of
 * credential would be a second thing to rotate and revoke.
 *
 * The handle is bound to the app that will redeem it whenever the caller says which
 * app that is. An unbound handle can be redeemed by whichever app presents it first,
 * which is only acceptable when the EHR genuinely does not know - and the console's
 * simulator always knows, so it always binds.
 *
 * Author: John Grimes
 */

import { validateLaunchContext } from "@signet/core";
import {
  createLaunchContext,
  generateOpaqueToken,
  hashToken,
  isClientUsable,
  resolveClientScope,
  withTenantScope,
} from "@signet/db";

import {
  authenticateClient,
  credentialFieldsFrom,
} from "./clientAuthentication.js";
import { oauthErrorBody, statusForTokenError } from "../http/oauthErrors.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { FormBody } from "./grants/types.js";
import type { ClientScope } from "@signet/db";
import type { Context } from "hono";

/**
 * How long a launch handle may sit unredeemed, in seconds.
 *
 * Five minutes. A handle is minted at the moment a clinician clicks an app in the
 * EHR, so the interval between minting and redemption is a browser navigation. A
 * generous window would leave redeemable handles lying in EHR logs.
 */
export const LAUNCH_CONTEXT_TTL_SECONDS = 300;

/** The request body, before validation. */
interface LaunchContextBody {
  readonly patient?: unknown;
  readonly encounter?: unknown;
  readonly fhirContext?: unknown;
  readonly intent?: unknown;
  readonly tenant?: unknown;
  readonly needPatientBanner?: unknown;
  readonly smartStyleUrl?: unknown;
  /** The `client_id` permitted to redeem the handle. */
  readonly forClientId?: unknown;
  // The credential may travel in the JSON body as well as in the `Authorization`
  // header, because a `private_key_jwt` client has nowhere else to put its
  // assertion when the body is JSON rather than form-encoded.
  readonly client_id?: unknown;
  readonly client_secret?: unknown;
  readonly client_assertion?: unknown;
  readonly client_assertion_type?: unknown;
}

/** Lifts the credential fields out of a JSON body, keeping only strings. */
function credentialsFromJson(body: LaunchContextBody): FormBody {
  const fields: Record<string, string> = {};
  for (const name of [
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
  ] as const) {
    const value = body[name];
    if (typeof value === "string") {
      fields[name] = value;
    }
  }
  return fields;
}

/**
 * Handles `POST` on the launch-context endpoint.
 *
 * @param context - The server's dependencies.
 */
export function launchContextHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(context, c);

    if (!issuerContext.endpoint.supportsEhrLaunch) {
      return c.json(
        oauthErrorBody(
          "invalid_request",
          "This endpoint does not support the EHR launch",
        ),
        404,
      );
    }

    // The context is JSON, because `fhirContext` has nested structure that form
    // encoding cannot carry - so the body is read before the credential, which may
    // be in it.
    const body = (await c.req.json().catch(() => ({}))) as LaunchContextBody;

    const authentication = await authenticateClient(
      context,
      issuerContext,
      c.req.header("authorization"),
      credentialFieldsFrom(credentialsFromJson(body)),
    );
    if (!authentication.ok) {
      return c.json(
        oauthErrorBody(authentication.code, authentication.description),
        statusForTokenError(authentication.code),
      );
    }
    const caller = authentication.authenticated;

    // Only the fields a launch context may carry are read, and each is checked for
    // type. Passing the body through to `validateLaunchContext` would let an
    // unknown key ride along into the stored row and out again into a token.
    const candidate = {
      ...(typeof body.patient === "string" ? { patient: body.patient } : {}),
      ...(typeof body.encounter === "string"
        ? { encounter: body.encounter }
        : {}),
      ...(Array.isArray(body.fhirContext)
        ? { fhirContext: body.fhirContext }
        : {}),
      ...(typeof body.intent === "string" ? { intent: body.intent } : {}),
      ...(typeof body.tenant === "string" ? { tenant: body.tenant } : {}),
      ...(typeof body.needPatientBanner === "boolean"
        ? { needPatientBanner: body.needPatientBanner }
        : {}),
      ...(typeof body.smartStyleUrl === "string"
        ? { smartStyleUrl: body.smartStyleUrl }
        : {}),
    };

    const validation = validateLaunchContext(candidate);
    if (!validation.ok) {
      return c.json(
        {
          ...oauthErrorBody(
            "invalid_request",
            "The launch context is not valid",
          ),
          issues: validation.issues,
        },
        400,
      );
    }

    let boundTo: ClientScope | undefined;
    if (body.forClientId !== undefined) {
      if (typeof body.forClientId !== "string") {
        return c.json(
          oauthErrorBody("invalid_request", "forClientId must be a string"),
          400,
        );
      }
      const forClientId = body.forClientId;
      const target = await withTenantScope(
        context.db,
        issuerContext.scope,
        (bound) => resolveClientScope(bound, forClientId),
      );
      if (target === undefined || !isClientUsable(target.client)) {
        return c.json(
          oauthErrorBody(
            "invalid_request",
            "forClientId does not name an active client on this endpoint",
          ),
          400,
        );
      }
      boundTo = target.scope;
    }

    const handle = generateOpaqueToken();
    const row = await withTenantScope(
      context.db,
      issuerContext.scope,
      async (bound) =>
        createLaunchContext(bound, {
          handleHash: await hashToken(handle),
          context: validation.context,
          createdBy: `client:${caller.client.clientId}`,
          expiresAt: new Date(
            context.clock().getTime() + LAUNCH_CONTEXT_TTL_SECONDS * 1000,
          ),
          ...(boundTo === undefined ? {} : { boundTo }),
        }),
    );

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: issuerContext.endpoint.id,
      endpointSlug: issuerContext.endpoint.slug,
      actor: { type: "client", id: caller.client.clientId },
      action: "launch-context.created",
      target: { type: "launch-context", id: row.id },
      detail: {
        patient: validation.context.patient,
        encounter: validation.context.encounter,
        boundTo: body.forClientId,
      },
      ...metadata,
    });

    c.header("Cache-Control", "no-store");
    return c.json(
      {
        launch: handle,
        iss: issuerContext.issuer,
        expires_in: LAUNCH_CONTEXT_TTL_SECONDS,
      },
      201,
    );
  };
}
