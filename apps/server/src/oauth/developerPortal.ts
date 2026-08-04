/**
 * The developer portal's API: asking for a client, and collecting it.
 *
 * The surface exists because a connectathon or a marketplace has more app developers
 * than administrators, and an administrator's time is better spent approving a request
 * than transcribing one. It is also the reason the endpoint has a
 * `supportsDynamicRegistration`-adjacent decision to make: this is *not* dynamic
 * registration. RFC 7591 registration mints a client immediately; this files a request
 * that a human reviews, which is the right shape when the thing being handed out is
 * access to clinical data.
 *
 * Authentication is a token rather than an account. A developer asking for a client has
 * no account yet, and inventing one would mean a third kind of identity to manage
 * alongside administrators and end users. So a submission returns an opaque tracking
 * token once, stored as a digest, and following the request up requires presenting it
 * with the request's identifier. That is enough to collect a client secret, which is why
 * it is a real credential and not the identifier alone.
 *
 * The route is off unless the endpoint says otherwise. An endpoint fronting production
 * data should not accept registration requests from anybody who can reach the port, and
 * the flag that permits it is the same one that permits dynamic registration - both are
 * "this endpoint takes self-serve requests".
 *
 * Author: John Grimes
 */

import { clientRequestSchema } from "@signet/contracts";
import {
  createClientRequest,
  findClientRequestByTrackingToken,
  generateOpaqueToken,
  getClient,
  getClientByClientId,
  hashToken,
  withTenantScope,
} from "@signet/db";

import { bearerToken } from "../http/bearer.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { ClientRequest } from "@signet/db";
import type { Context } from "hono";

/** What the portal says about a request, whatever its state. */
function requestView(request: ClientRequest): Record<string, unknown> {
  return {
    id: request.id,
    status: request.status,
    name: request.payload.name,
    requestedScopes: request.payload.requestedScopes,
    redirectUris: request.payload.redirectUris,
    submittedAt: request.createdAt,
    decidedAt: request.decidedAt,
    /** The reviewer's note, which is where a rejection's reason lives. */
    decisionNote: request.decisionNote,
  };
}

/** The refusal an endpoint that does not take requests gives. */
function notAccepted(c: Context<SignetEnvironment>) {
  return c.json(
    {
      error: "not_found",
      error_description:
        "This endpoint does not accept self-serve client registration requests",
    },
    404,
  );
}

/**
 * Handles `POST {iss}/apps/requests`: files a registration request.
 *
 * @param context - The server's dependencies.
 */
export function submitClientRequestHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint } = issuerContext;
    const metadata = requestMetadata(c);

    if (!endpoint.supportsDynamicRegistration) {
      return notAccepted(c);
    }

    const raw: unknown = await c.req.json().catch(() => ({}));
    const parsed = clientRequestSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json(
        {
          error: "invalid_request",
          error_description: "That request is not valid",
          issues: parsed.error.issues.map((issue) => ({
            path: issue.path.map(String).join("."),
            message: issue.message,
          })),
        },
        400,
      );
    }

    const trackingToken = generateOpaqueToken();
    const trackingTokenHash = await hashToken(trackingToken);
    const request = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) =>
        createClientRequest(bound, {
          requestedByEmail: parsed.data.contactEmail,
          // The optional fields are dropped rather than stored as undefined: the payload is
          // retained verbatim as the record of what was asked for, and a key holding nothing
          // is not something anybody asked for.
          payload: {
            name: parsed.data.name,
            clientType: parsed.data.clientType,
            redirectUris: parsed.data.redirectUris,
            requestedScopes: parsed.data.requestedScopes,
            contactEmail: parsed.data.contactEmail,
            ...(parsed.data.description === undefined
              ? {}
              : { description: parsed.data.description }),
            ...(parsed.data.logoUrl === undefined
              ? {}
              : { logoUrl: parsed.data.logoUrl }),
            ...(parsed.data.launchUri === undefined
              ? {}
              : { launchUri: parsed.data.launchUri }),
            ...(parsed.data.note === undefined
              ? {}
              : { note: parsed.data.note }),
          },
          trackingTokenHash,
        }),
    );

    await context.audit.record(context.db, {
      tenantId: issuerContext.tenant.id,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
      // No identity to attribute this to: the submitter has no account, which is the
      // point of the surface. The email they gave is in the detail.
      actor: { type: "system" },
      action: "client-request.submitted",
      target: { type: "client-request", id: request.id },
      detail: {
        contactEmail: parsed.data.contactEmail,
        name: parsed.data.name,
        requestedScopes: parsed.data.requestedScopes,
      },
      ...metadata,
    });

    c.header("Cache-Control", "no-store");
    return c.json(
      {
        request: requestView(request),
        /**
         * Shown once. Kept by the developer to follow the request up; only its digest
         * is stored, so this response is the one opportunity to copy it.
         */
        trackingToken,
      },
      201,
    );
  };
}

/**
 * Handles `GET {iss}/apps/requests/:requestId`: the request's state, and its
 * credentials once approved.
 *
 * The tracking token is presented as a bearer credential. A request that has been
 * approved carries the client identifier; the secret is *not* returned here, because it
 * exists in exactly one response - the approval, in the console - and an endpoint that
 * could hand it out again would be a way to read a credential out of the database.
 *
 * @param context - The server's dependencies.
 */
export function clientRequestStatusHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    if (!issuerContext.endpoint.supportsDynamicRegistration) {
      return notAccepted(c);
    }

    const presented = bearerToken(c.req.header("authorization"));
    if (presented === undefined) {
      return c.json(
        {
          error: "unauthenticated",
          error_description:
            "Present the tracking token you were given when you filed the request",
        },
        401,
      );
    }

    // Hashed before the transaction opens. Nothing that takes measurable CPU
    // belongs inside one: a transaction holds a pooled connection, and hashing is
    // not a database operation.
    const presentedHash = await hashToken(presented);
    const request = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) =>
        findClientRequestByTrackingToken(
          bound,
          c.req.param("requestId") ?? "",
          presentedHash,
        ),
    );
    if (request === undefined) {
      // One answer for an unknown request and a wrong token: distinguishing them
      // would let a caller confirm that a request identifier exists.
      return c.json(
        {
          error: "not_found",
          error_description: "No such request, or that token does not match it",
        },
        404,
      );
    }

    let clientId: string | undefined;
    const resultingClientId = request.resultingClientId;
    if (resultingClientId !== null) {
      // The row references the client by surrogate key and the developer needs the
      // OAuth identifier. Read through the endpoint scope, which is what proves the
      // client belongs to the endpoint the request was filed against.
      const client = await withTenantScope(
        context.db,
        issuerContext.scope,
        (bound) => getClient(bound, resultingClientId),
      );
      clientId = client?.clientId;
    }

    c.header("Cache-Control", "no-store");
    return c.json({
      request: requestView(request),
      ...(clientId === undefined ? {} : { clientId }),
      ...(clientId === undefined
        ? {}
        : {
            /** What the developer needs to configure their app. */
            issuer: issuerContext.issuer,
            wellKnown: `${issuerContext.issuer}/.well-known/smart-configuration`,
          }),
    });
  };
}

/**
 * Handles `GET {iss}/apps/registration/:clientId`: what an app needs to configure
 * itself.
 *
 * Public on purpose, and carries nothing secret: the client identifier is already known
 * to whoever is asking, and everything else here is in the discovery document. It exists
 * so the portal can show a developer their app's registration without an administrator
 * copying fields out of the console.
 *
 * @param context - The server's dependencies.
 */
export function clientRegistrationHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const client = await withTenantScope(
      context.db,
      issuerContext.scope,
      (bound) => getClientByClientId(bound, c.req.param("clientId") ?? ""),
    );
    if (client === undefined) {
      return c.json(
        { error: "not_found", error_description: "No such client" },
        404,
      );
    }

    return c.json({
      clientId: client.clientId,
      name: client.name,
      clientType: client.clientType,
      redirectUris: client.redirectUris,
      launchUri: client.launchUri,
      grantTypes: client.grantTypes,
      allowedScopes: client.allowedScopes,
      status: client.status,
      issuer: issuerContext.issuer,
      wellKnown: `${issuerContext.issuer}/.well-known/smart-configuration`,
    });
  };
}
