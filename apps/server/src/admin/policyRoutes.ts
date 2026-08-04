/**
 * Policy versions, and the simulator the editor is built around.
 *
 * Versions are immutable. Editing a policy creates a new version; publishing points
 * the endpoint at one. That is what makes a rollback a publish rather than a restore,
 * and what lets the console show a diff between what is live and what is proposed.
 * The database enforces at most one published version per endpoint, so token
 * issuance can never depend on row order.
 *
 * The simulator is the reason the policy editor is usable at all. It takes a policy
 * document *in the request* - not a stored version - so an unsaved edit can be
 * previewed, and it runs `simulateIssuance`, which is the same composition the token
 * endpoint uses. Nothing is signed, stored or issued: a simulation is a pure function
 * of a policy and a context, which is what makes it safe to run on every keystroke.
 *
 * It simulates as a *registered* client and a *real* end user, identified by their
 * rows rather than described in the request. A simulator that accepted an invented
 * user would answer a question about a person who does not exist, and would be a way
 * to probe what a policy does with roles the tenant has not defined.
 *
 * Author: John Grimes
 */

import {
  policySimulationSchema,
  policyVersionCreateSchema,
} from "@signet/contracts";
import { parseScopes, simulateIssuance, toLaunchContext } from "@signet/core";
import {
  clientScopeFromRow,
  createPolicyVersion,
  getClientByClientId,
  getEffectivePolicy,
  getEndUser,
  getPolicyVersion,
  getPublishedPolicy,
  listPolicyVersions,
  publishPolicy,
  toEvaluationClient,
  toEvaluationEndpoint,
  toEvaluationUser,
  withTenantScope,
} from "@signet/db";

import { recordAdminEvent } from "./auditTrail.js";
import { requireRole } from "./authentication.js";
import { adminErrorBody, statusForAdminError } from "./errors.js";
import { ENDPOINT_PATH } from "./paths.js";
import { principalAdminUserId } from "./principal.js";
import { parseBody } from "./requestBody.js";
import { policyView } from "./views.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { Context, Hono } from "hono";

/**
 * Reads the version from the path, or the 400 to answer with.
 *
 * A version is a small integer allocated by the database, so anything else in that
 * segment is a mistake rather than a version that does not exist - 400 rather than
 * 404, which is the difference between "that is not a version" and "there is no such
 * version".
 *
 * @param c - The Hono request context.
 */
function requestedVersion(c: Context<SignetEnvironment>): number | Response {
  const version = Number(c.req.param("version"));
  if (!Number.isInteger(version)) {
    return c.json(
      adminErrorBody("invalid_request", "The version must be an integer"),
      statusForAdminError("invalid_request"),
    );
  }
  return version;
}

/**
 * Registers the policy routes.
 *
 * @param router - The admin API router.
 * @param context - The server's dependencies.
 */
export function registerPolicyRoutes(
  router: Hono<SignetEnvironment>,
  context: ServerContext,
): void {
  /** Lists every version, newest first, with the published one flagged. */
  router.get(`${ENDPOINT_PATH}/policies`, requireRole("viewer"), async (c) => {
    const { scope } = c.get("endpoint");
    const versions = await listPolicyVersions(context.db, scope);
    return c.json({ policies: versions.map(policyView) });
  });

  /**
   * Creates a version, optionally publishing it.
   *
   * The document has already been validated by the contract, which delegates to the
   * core validator - so a document that reaches here is one the evaluator accepts.
   */
  router.post(`${ENDPOINT_PATH}/policies`, requireRole("admin"), async (c) => {
    const { scope, endpoint } = c.get("endpoint");
    const body = await parseBody(c, policyVersionCreateSchema);
    if (body instanceof Response) {
      return body;
    }

    const created = await createPolicyVersion(context.db, scope, {
      document: body.document,
      createdBy: principalAdminUserId(c.get("principal")),
      note: body.note ?? null,
    });
    if (!created.ok) {
      return c.json(
        adminErrorBody("not_found", "No such endpoint"),
        statusForAdminError("not_found"),
      );
    }

    await recordAdminEvent(context, c, {
      action: "policy.created",
      target: { type: "policy", id: created.policy.id },
      detail: {
        version: created.policy.version,
        endpointSlug: endpoint.slug,
        note: body.note ?? null,
      },
    });

    let policy = created.policy;
    if (body.publish === true) {
      const published = await publishPolicy(
        context.db,
        scope,
        created.policy.version,
      );
      if (!published.ok) {
        return c.json(
          adminErrorBody("conflict", "That version could not be published"),
          statusForAdminError("conflict"),
        );
      }
      policy = published.policy;
      await recordAdminEvent(context, c, {
        action: "policy.published",
        target: { type: "policy", id: policy.id },
        detail: { version: policy.version, endpointSlug: endpoint.slug },
      });
    }

    return c.json({ policy: policyView(policy) }, 201);
  });

  /** Reads one version. */
  router.get(
    `${ENDPOINT_PATH}/policies/:version`,
    requireRole("viewer"),
    async (c) => {
      const { scope } = c.get("endpoint");
      const version = requestedVersion(c);
      if (version instanceof Response) {
        return version;
      }

      const policy = await getPolicyVersion(context.db, scope, version);
      if (policy === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such policy version"),
          statusForAdminError("not_found"),
        );
      }
      return c.json({ policy: policyView(policy) });
    },
  );

  /**
   * Publishes a version.
   *
   * The whole rollback story: an operator who has just published a mistake
   * republishes the version before it, and every token issued from that moment uses
   * it. Nothing is edited, so the mistake stays in the history where it can be read.
   */
  router.post(
    `${ENDPOINT_PATH}/policies/:version/publish`,
    requireRole("admin"),
    async (c) => {
      const { scope, endpoint } = c.get("endpoint");
      const version = requestedVersion(c);
      if (version instanceof Response) {
        return version;
      }

      const published = await publishPolicy(context.db, scope, version);
      if (!published.ok) {
        return c.json(
          adminErrorBody(
            "not_found",
            published.reason === "version-not-found"
              ? "No such policy version"
              : "No such endpoint",
          ),
          statusForAdminError("not_found"),
        );
      }

      await recordAdminEvent(context, c, {
        action: "policy.published",
        target: { type: "policy", id: published.policy.id },
        detail: { version, endpointSlug: endpoint.slug },
      });

      return c.json({ policy: policyView(published.policy) });
    },
  );

  /**
   * Simulates an issuance.
   *
   * Answers with what the token endpoint would produce: the granted scopes, what was
   * denied and why, what was narrowed, and the decoded claims of both tokens.
   */
  router.post(
    `${ENDPOINT_PATH}/policies/simulate`,
    requireRole("viewer"),
    async (c) => {
      const { scope, endpoint, issuer } = c.get("endpoint");
      const body = await parseBody(c, policySimulationSchema);
      if (body instanceof Response) {
        return body;
      }

      const client = await withTenantScope(context.db, scope, (bound) =>
        getClientByClientId(bound, body.clientId),
      );
      if (client === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such client on this endpoint"),
          statusForAdminError("not_found"),
        );
      }

      const user =
        body.endUserId === undefined
          ? undefined
          : await getEndUser(context.db, scope, body.endUserId);
      if (body.endUserId !== undefined && user === undefined) {
        return c.json(
          adminErrorBody("not_found", "No such user on this endpoint"),
          statusForAdminError("not_found"),
        );
      }

      // A policy in the request wins, so an unsaved edit can be previewed. With none,
      // the effective policy is used - including a client override, since that is
      // what this client would actually be issued under.
      let document = body.document;
      let simulatedVersion: number | null = null;
      if (document === undefined) {
        const effective = await getEffectivePolicy(
          context.db,
          clientScopeFromRow(scope, client),
        );
        if (effective === undefined) {
          return c.json(
            adminErrorBody(
              "conflict",
              "This endpoint has no published policy to simulate. Publish one, or send a document to preview.",
            ),
            statusForAdminError("conflict"),
          );
        }
        document = effective.document;
        const published = await getPublishedPolicy(context.db, scope);
        simulatedVersion = published?.version ?? null;
      }

      const parsed = parseScopes(body.requestedScopes);
      const result = simulateIssuance({
        policy: document,
        context: {
          endpoint: toEvaluationEndpoint(endpoint, scope.tenantSlug, issuer),
          client: toEvaluationClient(client),
          user: user === undefined ? null : toEvaluationUser(user),
          requested: parsed.scopes,
          context: toLaunchContext(body.context ?? {}),
          grantType: body.grantType ?? "authorization_code",
        },
        issuance: {
          jti: crypto.randomUUID(),
          issuedAt: Math.floor(context.clock().getTime() / 1000),
          subject: user?.id ?? client.clientId,
        },
        supportsOpenIdConnect: endpoint.supportsOpenIdConnect,
      });

      return c.json({
        /** Scopes the request asked for that are not valid SMART scopes at all. */
        rejectedScopes: parsed.rejected,
        scope: result.scope,
        granted: result.evaluation.grantedScopes,
        denied: result.evaluation.deniedScopes,
        narrowed: result.evaluation.narrowedScopes,
        accessTokenClaims: result.accessTokenClaims,
        idTokenClaims: result.idTokenClaims,
        responseParameters: result.responseParameters,
        accessTokenTtl: result.accessTokenTtl,
        refreshTokenTtl: result.refreshTokenTtl,
        wouldIssueRefreshToken: result.wouldIssueRefreshToken,
        simulatedVersion,
      });
    },
  );
}
