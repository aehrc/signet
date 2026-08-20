/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Registered clients, and the self-serve queue that produces them.
 *
 * A client secret exists in a response body exactly once, at creation or rotation,
 * and only its Argon2id digest is stored. There is deliberately no route that
 * returns one: a lost secret is rotated, not recovered, and any endpoint that could
 * return a secret would be a way to read one out of the database.
 *
 * The endpoint's client-type flags are enforced here rather than left to the token
 * endpoint. An endpoint that does not allow public clients should refuse to register
 * one, not register it and then refuse every authorization it attempts - the second
 * produces a client that appears configured and never works.
 *
 * Approving a registration request registers a client from the *administrator's*
 * body, not from the developer's payload. The payload is retained verbatim as the
 * record of what was asked for, so narrowing a scope or correcting a redirect URI at
 * approval time leaves the difference visible.
 *
 * Author: John Grimes
 */

import {
  clientCreateSchema,
  clientPatchSchema,
  clientRequestDecisionSchema,
  clientSecretRotationSchema,
} from "@signet/contracts";
import {
  approveClientRequest,
  clientScopeFromRow,
  createClient,
  deleteClient,
  endpointAllowsClientType,
  getClientByClientId,
  getClientRequest,
  hashPassword,
  isUniqueViolation,
  listClientRequests,
  listClients,
  rejectClientRequest,
  revokeAccessTokensForClient,
  revokeRefreshTokensForClient,
  setClientCredentials,
  updateClient,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { generateClientId, generateClientSecret } from "./credentials.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { principalAdminUserId } from "./principal.js";
import { definedFields, parseBody } from "./requestBody.js";
import { clientRequestView, clientView } from "./views.js";

import type { AdminEndpointContext } from "../context.js";
import type { ServerContext, SignetEnvironment } from "../context.js";
import type { ClientCreate } from "@signet/contracts";
import type { ClientInput, DecisionInput, DecisionRefusal } from "@signet/db";
import type { Context, Hono } from "hono";

/** The review states a registration request can be filtered by. */
const REVIEW_STATES = ["pending", "approved", "rejected"] as const;

/** Narrows a query parameter to a review state. */
function isReviewState(value: string): value is (typeof REVIEW_STATES)[number] {
  return (REVIEW_STATES as readonly string[]).includes(value);
}

/**
 * Answers a decision the data layer would not record.
 *
 * "Not found" and "already decided" are deliberately different answers: an
 * administrator who has just been beaten to a review by a colleague should be told
 * so, rather than being shown a 404 that looks like a bug.
 *
 * @param c - The Hono request context.
 * @param reason - Why the data layer declined.
 */
function refuseDecision(
  c: Context<SignetEnvironment>,
  reason: DecisionRefusal,
) {
  return reason === "not-found"
    ? c.json(
        adminErrorBody("not_found", "No such registration request"),
        statusForAdminError("not_found"),
      )
    : c.json(
        adminErrorBody(
          "conflict",
          "Somebody has already reviewed this request",
        ),
        statusForAdminError("conflict"),
      );
}

/**
 * Builds the record of who decided and what they said about it.
 *
 * @param c - The Hono request context, carrying the principal.
 * @param decisionNote - The reviewer's note, when they left one.
 */
function decisionFrom(
  c: Context<SignetEnvironment>,
  decisionNote: string | undefined,
): DecisionInput {
  return {
    reviewerId: principalAdminUserId(c.get("principal")),
    ...(decisionNote === undefined ? {} : { decisionNote }),
  };
}

/** The insert a validated create body describes, and the secret it generated. */
interface PreparedClient {
  readonly input: ClientInput;
  /** Present only for a symmetric client; shown to the caller once. */
  readonly secret?: string;
}

/**
 * Turns a create body into the row to insert.
 *
 * A symmetric client gets a secret whether or not one was supplied, because a
 * confidential client with no credential cannot authenticate and there is no useful
 * intermediate state to leave it in. Public and asymmetric clients get none: for the
 * first there is nothing to keep it in, and for the second the credential is the key.
 *
 * @param body - A validated create body.
 */
async function prepareClient(body: ClientCreate): Promise<PreparedClient> {
  const secret =
    body.clientType === "confidential-symmetric"
      ? (body.secret ?? generateClientSecret())
      : undefined;

  return {
    input: {
      clientId: body.clientId ?? generateClientId(body.name),
      name: body.name,
      clientType: body.clientType,
      ...(body.description === undefined
        ? {}
        : { description: body.description }),
      ...(body.logoUrl === undefined ? {} : { logoUrl: body.logoUrl }),
      ...(secret === undefined
        ? {}
        : { secretHash: await hashPassword(secret) }),
      ...(body.secretExpiresAt === undefined
        ? {}
        : { secretExpiresAt: body.secretExpiresAt }),
      ...(body.jwks === undefined ? {} : { jwks: body.jwks }),
      ...(body.jwksUri === undefined ? {} : { jwksUri: body.jwksUri }),
      redirectUris: body.redirectUris ?? [],
      ...(body.launchUri === undefined ? {} : { launchUri: body.launchUri }),
      grantTypes: body.grantTypes ?? ["authorization_code"],
      allowedScopes: body.allowedScopes ?? [],
      // Active on creation, because an administrator creating a client through the
      // console has already made the decision `pending` exists to defer. The
      // self-serve queue is where `pending` belongs.
      status: body.status ?? "active",
      ...(body.contactEmail === undefined
        ? {}
        : { contactEmail: body.contactEmail }),
      ...(body.attributes === undefined ? {} : { attributes: body.attributes }),
    },
    ...(secret === undefined ? {} : { secret }),
  };
}

/** Reads the client named in the path, or the 404 to answer with. */
async function loadClient(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  endpointContext: AdminEndpointContext,
) {
  const client = await withTenantScope(
    context.db,
    endpointContext.scope,
    (bound) => getClientByClientId(bound, c.req.param("clientId") ?? ""),
  );
  if (client === undefined) {
    return c.json(
      adminErrorBody("not_found", "No such client on this endpoint"),
      statusForAdminError("not_found"),
    );
  }
  return client;
}

/**
 * Registers the client and registration-request routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerClientRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Lists the endpoint's clients. */
  router.get(`${ENDPOINT_PATH}/clients`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("endpoint");
    const clients = await withTenantScope(context.db, scope, (bound) =>
      listClients(bound),
    );
    return c.json({ clients: clients.map(clientView) });
  });

  /** Registers a client. */
  router.post(
    `${ENDPOINT_PATH}/clients`,
    requireRole("developer"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const body = await parseBody(c, clientCreateSchema);
      if (body instanceof Response) {
        return body;
      }

      if (!endpointAllowsClientType(endpoint, body.clientType)) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            `This endpoint does not allow ${body.clientType} clients`,
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const prepared = await prepareClient(body);
      let client;
      try {
        client = await withTenantScope(context.db, scope, (bound) =>
          createClient(bound, {
            ...prepared.input,
            createdBy: principalAdminUserId(c.get("principal")),
          }),
        );
      } catch (error) {
        if (isUniqueViolation(error)) {
          // `client_id` is unique across the deployment, not per endpoint, so a
          // collision may be with a client on somebody else's endpoint. The message
          // says only that the identifier is taken.
          return c.json(
            adminErrorBody(
              "conflict",
              "That client identifier is already registered",
            ),
            statusForAdminError("conflict"),
          );
        }
        throw error;
      }

      await recordAdminEvent(context, c, {
        action: "client.created",
        target: { type: "client", id: client.clientId },
        detail: {
          name: client.name,
          clientType: client.clientType,
          grantTypes: client.grantTypes,
          allowedScopes: client.allowedScopes,
        },
      });

      c.header("Cache-Control", "no-store");
      return c.json(
        {
          client: clientView(client),
          ...(prepared.secret === undefined ? {} : { secret: prepared.secret }),
        },
        201,
      );
    },
  );

  /** Reads one client. */
  router.get(
    `${ENDPOINT_PATH}/clients/:clientId`,
    requireRole("viewer"),
    async (c) => {
      const client = await loadClient(c, context, c.get("endpoint"));
      if (client instanceof Response) {
        return client;
      }
      return c.json({ client: clientView(client) });
    },
  );

  /**
   * Edits a client.
   *
   * Suspending one - `status: "suspended"` - also revokes its live tokens. A
   * suspension that left issued tokens working would take effect only at the next
   * token request, which for a backend service holding a five-minute token is not
   * what an operator means by "suspend".
   */
  router.patch(
    `${ENDPOINT_PATH}/clients/:clientId`,
    requireRole("developer"),
    async (c) => {
      const endpointContext = c.get("endpoint");
      const existing = await loadClient(c, context, endpointContext);
      if (existing instanceof Response) {
        return existing;
      }

      const body = await parseBody(c, clientPatchSchema);
      if (body instanceof Response) {
        return body;
      }

      const patch = definedFields(body);
      const updated = await withTenantScope(
        context.db,
        clientScopeFromRow(endpointContext.scope, existing),
        (bound) => updateClient(bound, patch, context.clock()),
      );
      if (updated === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such client"),
          statusForAdminError("not_found"),
        );
      }

      const suspended =
        body.status === "suspended" && existing.status !== "suspended";
      if (suspended) {
        const clientScope = clientScopeFromRow(endpointContext.scope, updated);
        await withTenantScope(context.db, clientScope, (bound) =>
          revokeAccessTokensForClient(bound, context.clock()),
        );
        await withTenantScope(context.db, clientScope, (bound) =>
          revokeRefreshTokensForClient(bound, context.clock()),
        );
      }

      await recordAdminEvent(context, c, {
        action: suspended ? "client.suspended" : "client.updated",
        target: { type: "client", id: updated.clientId },
        detail: { fields: Object.keys(patch) },
      });

      return c.json({ client: clientView(updated) });
    },
  );

  /**
   * Rotates a symmetric client's secret.
   *
   * The old secret stops working immediately. Overlapping secrets would be kinder to
   * a deployment mid-rollout, but two live secrets means a leaked one stays usable
   * for as long as the rotation takes, and `clients` holds one digest by design.
   */
  router.post(
    `${ENDPOINT_PATH}/clients/:clientId/secret`,
    requireRole("developer"),
    async (c) => {
      const endpointContext = c.get("endpoint");
      const existing = await loadClient(c, context, endpointContext);
      if (existing instanceof Response) {
        return existing;
      }

      if (existing.clientType !== "confidential-symmetric") {
        return c.json(
          adminErrorBody(
            "invalid_request",
            `A ${existing.clientType} client has no secret to rotate`,
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const body = await parseBody(c, clientSecretRotationSchema);
      if (body instanceof Response) {
        return body;
      }

      const secret = body.secret ?? generateClientSecret();
      // Argon2id before the transaction opens, not inside it: hashing a password
      // deliberately takes a hundred milliseconds or more, and a transaction
      // holding a pooled connection for that long is a cost with no benefit.
      const secretHash = await hashPassword(secret);
      const updated = await withTenantScope(
        context.db,
        clientScopeFromRow(endpointContext.scope, existing),
        (bound) =>
          setClientCredentials(
            bound,
            {
              secretHash,
              secretExpiresAt: body.secretExpiresAt ?? null,
              jwks: existing.jwks,
              jwksUri: existing.jwksUri,
            },
            context.clock(),
          ),
      );
      if (updated === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such client"),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "client.secret-rotated",
        target: { type: "client", id: updated.clientId },
      });

      c.header("Cache-Control", "no-store");
      return c.json({ client: clientView(updated), secret });
    },
  );

  /**
   * Deletes a client.
   *
   * Cascades to its tokens, consents and codes. Suspending is usually what an
   * operator wants - it is reversible and keeps the registration visible - and the
   * console says so, but a client registered by mistake should be removable.
   */
  router.delete(
    `${ENDPOINT_PATH}/clients/:clientId`,
    requireRole("admin"),
    async (c) => {
      const endpointContext = c.get("endpoint");
      const existing = await loadClient(c, context, endpointContext);
      if (existing instanceof Response) {
        return existing;
      }

      await recordAdminEvent(context, c, {
        action: "client.deleted",
        target: { type: "client", id: existing.clientId },
        detail: { name: existing.name },
      });

      await withTenantScope(
        context.db,
        clientScopeFromRow(endpointContext.scope, existing),
        (bound) => deleteClient(bound),
      );
      return c.body(null, 204);
    },
  );

  /** Lists registration requests, optionally by review state. */
  router.get(
    `${ENDPOINT_PATH}/client-requests`,
    requireRole("viewer"),
    async (c) => {
      const { scope } = c.get("endpoint");
      const status = c.req.query("status");
      // Refused rather than ignored, for the same reason a malformed audit filter
      // is: "nothing is pending" and "that is not a review state" are different
      // answers, and the console should not have to guess which it got.
      if (status !== undefined && !isReviewState(status)) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            `status must be one of ${REVIEW_STATES.join(", ")}`,
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const requests = await withTenantScope(context.db, scope, (bound) =>
        listClientRequests(bound, status),
      );
      return c.json({ requests: requests.map(clientRequestView) });
    },
  );

  /**
   * Approves a request, registering the client it asked for.
   *
   * The administrator may send a `client` body that differs from the request's
   * payload; when they do not, the payload is registered as asked. Either way the
   * payload is kept, so the console can show what changed at approval.
   */
  router.post(
    `${ENDPOINT_PATH}/client-requests/:requestId/approve`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const requestId = c.req.param("requestId");
      const body = await parseBody(c, clientRequestDecisionSchema);
      if (body instanceof Response) {
        return body;
      }

      const request = await withTenantScope(context.db, scope, (bound) =>
        getClientRequest(bound, requestId),
      );
      if (request === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such registration request"),
          statusForAdminError("not_found"),
        );
      }

      const asRequested: ClientCreate = {
        name: request.payload.name,
        clientType: request.payload.clientType,
        redirectUris: [...request.payload.redirectUris],
        allowedScopes: [...request.payload.requestedScopes],
        contactEmail: request.payload.contactEmail,
        ...(request.payload.description === undefined
          ? {}
          : { description: request.payload.description }),
        ...(request.payload.logoUrl === undefined
          ? {}
          : { logoUrl: request.payload.logoUrl }),
        ...(request.payload.launchUri === undefined
          ? {}
          : { launchUri: request.payload.launchUri }),
        grantTypes: ["authorization_code", "refresh_token"],
      };
      const desired = body.client ?? asRequested;

      if (!endpointAllowsClientType(endpoint, desired.clientType)) {
        return c.json(
          adminErrorBody(
            "invalid_request",
            `This endpoint does not allow ${desired.clientType} clients`,
          ),
          statusForAdminError("invalid_request"),
        );
      }

      const prepared = await prepareClient(desired);
      const decision = await withTenantScope(context.db, scope, (bound) =>
        approveClientRequest(
          bound,
          requestId,
          decisionFrom(c, body.decisionNote),
          {
            ...prepared.input,
            createdBy: principalAdminUserId(c.get("principal")),
          },
          context.clock(),
        ),
      );

      if (!decision.ok) {
        return refuseDecision(c, decision.reason);
      }

      await recordAdminEvent(context, c, {
        action: "client-request.approved",
        target: { type: "client-request", id: requestId },
        detail: {
          clientId: decision.client.clientId,
          narrowed: body.client !== undefined,
        },
      });

      c.header("Cache-Control", "no-store");
      return c.json({
        request: clientRequestView(decision.request),
        client: clientView(decision.client),
        ...(prepared.secret === undefined ? {} : { secret: prepared.secret }),
      });
    },
  );

  /** Rejects a request, keeping the payload as the record of what was asked. */
  router.post(
    `${ENDPOINT_PATH}/client-requests/:requestId/reject`,
    requireRole("admin"),
    async (c) => {
      const { scope } = c.get("endpoint");
      const requestId = c.req.param("requestId");
      const body = await parseBody(c, clientRequestDecisionSchema);
      if (body instanceof Response) {
        return body;
      }

      const decision = await withTenantScope(context.db, scope, (bound) =>
        rejectClientRequest(
          bound,
          requestId,
          decisionFrom(c, body.decisionNote),
          context.clock(),
        ),
      );

      if (!decision.ok) {
        return refuseDecision(c, decision.reason);
      }

      await recordAdminEvent(context, c, {
        action: "client-request.rejected",
        target: { type: "client-request", id: requestId },
      });

      return c.json({ request: clientRequestView(decision.request) });
    },
  );
}
