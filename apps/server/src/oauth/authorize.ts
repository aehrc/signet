/**
 * The authorization endpoint.
 *
 * Its job is narrow and it is important that it stays narrow: validate the
 * request, resolve any launch context the EHR supplied, record everything
 * security-bearing in an `authorization_sessions` row, and hand the browser off to
 * the first interaction step. It issues no code and consults no policy - those
 * happen at the end of the interaction, from the row rather than from the browser.
 *
 * `POST` is supported only on endpoints that advertise the `authorize-post`
 * capability. It exists for requests whose scope string is too long for a URL,
 * which a `patient/`-per-resource-type app reaches sooner than one might expect.
 *
 * Author: John Grimes
 */

import { validateLaunchContext } from "@signet/core";
import {
  consumeLaunchContext,
  createAuthorizationSession,
  hashToken,
  resolveClientScope,
  setResolvedContext,
  withTenantScope,
} from "@signet/db";

import { validateAuthorizeRequest } from "./authorizeRequest.js";
import { interactionUrl } from "./interactionState.js";
import { authorizeErrorRedirect } from "../http/oauthErrors.js";
import { requestMetadata } from "../http/requestMeta.js";

import type { ServerContext, SignetEnvironment } from "../context.js";
import type { AuthorizeParams, AuthorizeRefusal } from "./authorizeRequest.js";
import type { FormBody } from "./grants/types.js";
import type { LaunchContext } from "@signet/core";
import type { ClientScope, LaunchHandleRefusal } from "@signet/db";
import type { Context } from "hono";

/**
 * How long an in-flight authorization may take, in seconds.
 *
 * Ten minutes covers signing in, picking a patient and reading a consent screen
 * without leaving abandoned sessions lying around for hours. It is not a security
 * boundary - the code it eventually produces lives for sixty seconds - but a
 * session that outlived the user's attention would let a shared browser complete
 * somebody else's authorization.
 */
export const AUTHORIZATION_SESSION_TTL_SECONDS = 600;

/** Why a launch handle could not be redeemed, in words an app developer can use. */
const LAUNCH_REFUSAL_DESCRIPTIONS: Readonly<
  Record<LaunchHandleRefusal, string>
> = {
  "not-found": "The launch parameter does not name a known launch context",
  "already-consumed": "This launch context has already been used",
  expired: "This launch context has expired",
  "client-mismatch": "This launch context was issued to a different app",
};

/** Reads the authorize parameters from a query string or a form body. */
function toAuthorizeParams(
  read: (name: string) => string | undefined,
): AuthorizeParams {
  return {
    responseType: read("response_type"),
    clientId: read("client_id"),
    redirectUri: read("redirect_uri"),
    scope: read("scope"),
    state: read("state"),
    aud: read("aud"),
    launch: read("launch"),
    codeChallenge: read("code_challenge"),
    codeChallengeMethod: read("code_challenge_method"),
    nonce: read("nonce"),
  };
}

/**
 * Reads a value from a parsed form body.
 *
 * A repeated field arrives as an array, and a repeated OAuth parameter is a
 * malformed request rather than a list - treating it as absent means the request
 * is refused for the missing parameter, which is the right outcome and avoids
 * having to decide which of two `redirect_uri` values the caller meant.
 */
function formReader(body: FormBody): (name: string) => string | undefined {
  return (name) => {
    const value = body[name];
    return typeof value === "string" && value.length > 0 ? value : undefined;
  };
}

/**
 * Resolves the launch context an EHR launch handle carries.
 *
 * The handle is consumed here rather than at the end of the interaction, and that
 * is deliberate: it is single-use, and consuming it at the start means an
 * abandoned authorization cannot leave a live handle behind for somebody else to
 * present.
 */
async function resolveEhrContext(
  context: ServerContext,
  scope: ClientScope,
  handle: string,
): Promise<
  | { readonly ok: true; readonly context: LaunchContext; readonly id: string }
  | { readonly ok: false; readonly description: string }
> {
  // Hashed before the transaction opens: nothing that is not a database
  // operation belongs inside one.
  const handleHash = await hashToken(handle);
  const redemption = await withTenantScope(context.db, scope, (bound) =>
    consumeLaunchContext(bound, handleHash),
  );
  if (!redemption.ok) {
    return {
      ok: false,
      description: LAUNCH_REFUSAL_DESCRIPTIONS[redemption.reason],
    };
  }

  // Re-validated on the way out as well as on the way in. The row was validated
  // when the EHR minted it, but a launch context is the one piece of a token's
  // contents that comes from a third party, and re-checking costs nothing.
  const validation = validateLaunchContext(redemption.launch.context);
  if (!validation.ok) {
    return {
      ok: false,
      description: `The launch context is not valid: ${validation.issues[0]?.message ?? "unknown"}`,
    };
  }

  return {
    ok: true,
    context: validation.context,
    id: redemption.launch.id,
  };
}

/**
 * Handles `GET` and `POST` on the authorization endpoint.
 *
 * @param context - The server's dependencies.
 */
export function authorizeHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint, scope, tenant } = issuerContext;
    const metadata = requestMetadata(c);

    if (c.req.method === "POST" && !endpoint.supportsAuthorizePost) {
      return c.json(
        {
          error: "invalid_request",
          error_description:
            "This endpoint does not support POST to the authorization endpoint",
        },
        405,
      );
    }

    const params =
      c.req.method === "POST"
        ? toAuthorizeParams(formReader(await c.req.parseBody()))
        : toAuthorizeParams((name) => c.req.query(name));

    /** Records a refusal and produces the response it calls for. */
    const deny = async (refusal: AuthorizeRefusal) => {
      await context.audit.record(context.db, {
        tenantId: tenant.id,
        endpointId: endpoint.id,
        endpointSlug: endpoint.slug,
        actor: {
          type: "client",
          ...(params.clientId === undefined ? {} : { id: params.clientId }),
        },
        action: "authorize.denied",
        target: { type: "client" },
        detail: {
          error: refusal.error,
          description: refusal.description,
          mode: refusal.mode,
          clientId: params.clientId,
          requestedScopes: params.scope,
        },
        ...metadata,
      });

      if (refusal.mode === "direct") {
        return c.json(
          { error: refusal.error, error_description: refusal.description },
          400,
        );
      }
      return c.redirect(
        authorizeErrorRedirect(
          refusal.redirectUri,
          refusal.error,
          refusal.description,
          refusal.state,
        ),
        302,
      );
    };

    const clientId = params.clientId;
    const resolved =
      clientId === undefined
        ? undefined
        : await withTenantScope(context.db, scope, (bound) =>
            resolveClientScope(bound, clientId),
          );

    const validation = validateAuthorizeRequest({
      params,
      endpoint,
      client: resolved?.client,
    });
    if (!validation.ok) {
      return await deny(validation.refusal);
    }
    const request = validation.request;

    // `resolved` is defined whenever the validation succeeded - it refuses an
    // unknown client before anything else - but the compiler cannot see that
    // through the pure function, and an assertion here would be a lie waiting to
    // become true.
    if (resolved === undefined) {
      return await deny({
        mode: "direct",
        error: "server_error",
        description: "The client could not be resolved",
      });
    }

    let launchContext: LaunchContext = {};
    let launchContextId: string | undefined;
    if (request.launch !== undefined) {
      const ehr = await resolveEhrContext(
        context,
        resolved.scope,
        request.launch,
      );
      if (!ehr.ok) {
        return await deny({
          mode: "redirect",
          redirectUri: request.redirectUri,
          error: "invalid_request",
          description: ehr.description,
          ...(request.state === undefined ? {} : { state: request.state }),
        });
      }
      launchContext = ehr.context;
      launchContextId = ehr.id;

      await context.audit.record(context.db, {
        tenantId: tenant.id,
        endpointId: endpoint.id,
        endpointSlug: endpoint.slug,
        actor: { type: "client", id: request.clientId },
        action: "launch-context.consumed",
        target: { type: "launch-context", id: ehr.id },
        detail: { patient: launchContext.patient },
        ...metadata,
      });
    }

    const session = await withTenantScope(context.db, resolved.scope, (bound) =>
      createAuthorizationSession(bound, {
        requestedScopes: [...request.requestedScopes],
        redirectUri: request.redirectUri,
        state: request.state ?? null,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: request.codeChallengeMethod,
        aud: request.aud,
        nonce: request.nonce ?? null,
        expiresAt: new Date(
          context.clock().getTime() + AUTHORIZATION_SESSION_TTL_SECONDS * 1000,
        ),
      }),
    );

    if (launchContextId !== undefined) {
      await withTenantScope(context.db, scope, (bound) =>
        setResolvedContext(bound, session.id, launchContext, launchContextId),
      );
    }

    await context.audit.record(context.db, {
      tenantId: tenant.id,
      endpointId: endpoint.id,
      endpointSlug: endpoint.slug,
      actor: { type: "client", id: request.clientId },
      action: "authorize.requested",
      target: { type: "authorization-session", id: session.id },
      detail: {
        clientId: request.clientId,
        launchMode: request.launchMode,
        requestedScopes: request.requestedScopes,
        redirectUri: request.redirectUri,
      },
      ...metadata,
    });

    // Always the login page, even when the session could in principle skip
    // straight past it: the page re-derives the step from the row and forwards, so
    // there is one entry point to the interaction rather than a second copy of the
    // step machine here.
    return c.redirect(
      interactionUrl(issuerContext.issuer, "login", session.id),
      302,
    );
  };
}
