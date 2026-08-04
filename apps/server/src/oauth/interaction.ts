/**
 * The interaction API: the server side of signing in, picking a patient and
 * consenting.
 *
 * These are JSON endpoints under the endpoint's issuer, and the browser-facing
 * pages at `{iss}/login`, `{iss}/picker` and `{iss}/consent` are a client of them.
 * Splitting it that way means the whole of the authorization flow is exercisable
 * without a browser, which is what makes the negative paths - resuming somebody
 * else's session, consenting before authenticating, choosing a patient the user
 * may not act on - testable at all.
 *
 * The invariant every handler upholds: nothing about the request is taken from the
 * client. Scopes, redirect URI, PKCE challenge and audience all come from the
 * `authorization_sessions` row written at `/authorize`, and each handler
 * re-derives the current step from that row rather than trusting the page that
 * posted to it. A caller that posts to `/consent` first is answered with
 * `step: "login"` and has consented to nothing.
 *
 * The session identifier is not a bearer credential. It is a database
 * identifier that grants nothing: reading a session tells the caller what the app
 * asked for, which the app already knows, and advancing one requires a credential
 * the session does not contain. Guessing one gains an attacker the ability to
 * complete an authorization *they* started.
 *
 * Author: John Grimes
 */

import {
  areScopesCoveredBy,
  parseScopes,
  validateLaunchContext,
} from "@signet/core";
import {
  attachEndUser,
  createAuthorizationCode,
  deleteAuthorizationSession,
  generateOpaqueToken,
  getClient,
  getEndUser,
  getIdpConfig,
  getLiveAuthorizationSession,
  hashToken,
  listLiveConsents,
  listSelectablePersonas,
  recordConsent,
  recordSessionConsent,
  resolveClientScope,
  setResolvedContext,
  toDefaultLaunchContext,
} from "@signet/db";

import {
  contextCandidates,
  isSelectableContextValue,
  soleCandidate,
} from "./contextCandidates.js";
import { contextRequirements } from "./contextRequirements.js";
import { recordEndUserEvent } from "./endUserAudit.js";
import {
  readEndUserCredentials,
  signInEndUser,
} from "./endUserAuthentication.js";
import { decideStep, interactionUrl } from "./interactionState.js";
import { authorizeErrorRedirect } from "../http/oauthErrors.js";
import { requestMetadata } from "../http/requestMeta.js";

import type {
  ServerContext,
  ResolvedIssuerContext,
  SignetEnvironment,
} from "../context.js";
import type { InteractionView, LaunchContextValues } from "@signet/contracts";
import type { LaunchContext, Scope } from "@signet/core";
import type {
  AuthorizationSession,
  Client,
  ClientScope,
  EndUser,
} from "@signet/db";
import type { Context } from "hono";

/**
 * How long an authorization code lives, in seconds.
 *
 * RFC 6749 §4.1.2 recommends a maximum of ten minutes and says a code should be
 * short-lived; sixty seconds is what a redirect and a token request actually need,
 * and the difference is a minute during which a leaked code is redeemable.
 */
export const AUTHORIZATION_CODE_TTL_SECONDS = 60;

/** A session loaded with the client it belongs to. */
interface LoadedSession {
  readonly session: AuthorizationSession;
  readonly clientScope: ClientScope;
  readonly client: Client;
  readonly requested: readonly Scope[];
}

/**
 * A session somebody has signed into.
 *
 * The narrowed `endUserId` is what the overloads on `loadForInteraction` deliver:
 * a handler that asked for an authenticated session gets one whose user is a
 * `string`, rather than having to re-check a column the guard already checked.
 */
type AuthenticatedSession = LoadedSession & {
  readonly session: AuthorizationSession & { readonly endUserId: string };
};

/**
 * Loads a live session and the client it belongs to.
 *
 * Endpoint-scoped and expiry-filtered in SQL, so an expired session and one
 * belonging to another endpoint are both simply absent - a handler that only calls
 * this cannot resume either.
 */
async function loadSession(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  sessionId: string,
): Promise<LoadedSession | undefined> {
  const session = await getLiveAuthorizationSession(
    context.db,
    issuerContext.scope,
    sessionId,
  );
  if (session === undefined) {
    return undefined;
  }

  // The session references the client by surrogate key; the scope has to be
  // rebuilt from a row, which is what proves the two belong together.
  const resolved = await resolveClientScopeForSession(
    context,
    issuerContext,
    session,
  );
  if (resolved === undefined) {
    return undefined;
  }

  return {
    session,
    clientScope: resolved.scope,
    client: resolved.client,
    requested: parseScopes(session.requestedScopes.join(" ")).scopes,
  };
}

/**
 * Recovers the `ClientScope` for a session's client.
 *
 * The session stores `clients.id`, and `resolveClientScope` takes the OAuth
 * `client_id`, so the row is read by primary key first. Doing it this way rather
 * than adding a by-surrogate-key resolver keeps the number of places that can mint
 * a `ClientScope` at four, as the data layer's documentation promises.
 */
async function resolveClientScopeForSession(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  session: AuthorizationSession,
): Promise<{ scope: ClientScope; client: Client } | undefined> {
  const client = await getClient(
    context.db,
    issuerContext.scope,
    session.clientId,
  );
  if (client === undefined) {
    return undefined;
  }
  return await resolveClientScope(
    context.db,
    issuerContext.scope,
    client.clientId,
  );
}

/** Whether a stored consent already covers everything the session requests. */
async function hasCoveringConsent(
  context: ServerContext,
  loaded: LoadedSession,
  endUserId: string,
): Promise<boolean> {
  const consents = await listLiveConsents(
    context.db,
    loaded.clientScope,
    endUserId,
    context.clock(),
  );
  return consents.some((consent) =>
    areScopesCoveredBy(loaded.requested, parseScopes(consent.scope).scopes),
  );
}

/** Derives the current step and everything the page for it needs. */
async function buildView(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  loaded: LoadedSession,
): Promise<InteractionView> {
  const { endpoint } = issuerContext;
  const { session, client } = loaded;
  const requirements = contextRequirements(loaded.requested);

  const user =
    session.endUserId === null
      ? undefined
      : await getEndUser(context.db, issuerContext.scope, session.endUserId);

  const step = decideStep({
    authenticated: user !== undefined,
    requirements,
    // Widened to the contract's record shape; a launch context is one.
    resolvedContext: session.resolvedContext,
    consentGranted: session.consentGrantedAt !== null,
    consentMode: endpoint.consentMode,
    hasStoredConsent:
      user === undefined
        ? false
        : await hasCoveringConsent(context, loaded, user.id),
  });

  const personas =
    user === undefined
      ? await listSelectablePersonas(context.db, issuerContext.scope, endpoint)
      : [];

  // Read only in `oidc` mode: an endpoint with local accounts has no provider to
  // name, and a stray row left behind by an operator who switched auth mode back
  // must not put a sign-in button on the page.
  const idp =
    endpoint.authMode === "oidc"
      ? await getIdpConfig(context.db, issuerContext.scope)
      : undefined;

  return {
    step,
    client: {
      clientId: client.clientId,
      name: client.name,
      logoUrl: client.logoUrl,
    },
    requestedScopes: session.requestedScopes,
    authMode: endpoint.authMode,
    allowsPersonas: !endpoint.isProduction,
    personas: personas.map((persona) => ({
      id: persona.id,
      displayName: persona.displayName,
      fhirUser: persona.fhirUserReference,
    })),
    requirements,
    patients: user === undefined ? [] : contextCandidates(user, "patient"),
    encounters: user === undefined ? [] : contextCandidates(user, "encounter"),
    allowsFreeContextSelection: !endpoint.isProduction,
    // Widened to the contract's record shape; a launch context is one.
    resolvedContext: session.resolvedContext as LaunchContextValues | null,
    ...(idp === undefined ? {} : { federation: { name: idp.displayName } }),
  };
}

/**
 * Issues the authorization code and builds the redirect that delivers it.
 *
 * The code is generated as an opaque token and stored only as a digest, so a
 * database disclosure yields nothing redeemable. It is bound to the session, and
 * the session carries the redirect URI and the PKCE challenge the token endpoint
 * will check - which is what makes a code stolen in transit useless without the
 * verifier.
 */
async function completeAuthorization(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  loaded: LoadedSession,
  metadata: ReturnType<typeof requestMetadata>,
): Promise<string> {
  const code = generateOpaqueToken();
  await createAuthorizationCode(
    context.db,
    issuerContext.scope,
    loaded.session,
    {
      codeHash: await hashToken(code),
      expiresAt: new Date(
        context.clock().getTime() + AUTHORIZATION_CODE_TTL_SECONDS * 1000,
      ),
    },
  );

  await recordEndUserEvent(context, issuerContext, metadata, {
    action: "authorize.code-issued",
    target: { type: "authorization-session", id: loaded.session.id },
    detail: {
      clientId: loaded.client.clientId,
      requestedScopes: loaded.session.requestedScopes,
    },
    endUserId: loaded.session.endUserId,
  });

  const url = new URL(loaded.session.redirectUri);
  url.searchParams.set("code", code);
  if (loaded.session.state !== null) {
    url.searchParams.set("state", loaded.session.state);
  }
  return url.toString();
}

/**
 * Answers a step, completing the authorization when nothing is outstanding.
 *
 * Every handler ends here, so the transition from `consent` to a redirect happens
 * in one place regardless of which step turned out to be last - an endpoint in
 * `auto` consent mode with an EHR-supplied context completes straight from login.
 */
async function respondWithStep(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  loaded: LoadedSession,
  metadata: ReturnType<typeof requestMetadata>,
) {
  const view = await buildView(context, issuerContext, loaded);
  if (view.step !== "complete") {
    return c.json(view);
  }
  return c.json({
    ...view,
    redirectTo: await completeAuthorization(
      context,
      issuerContext,
      loaded,
      metadata,
    ),
  });
}

/**
 * Re-reads the session and answers with whatever step it is now on.
 *
 * Every mutating handler ends with this. Re-reading rather than reasoning about
 * the row it just wrote means the step is always derived from committed state, so
 * two concurrent posts cannot produce two different views of the same session.
 */
async function respondAfterAdvance(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  loaded: LoadedSession,
  metadata: ReturnType<typeof requestMetadata>,
) {
  const refreshed = await loadSession(
    context,
    issuerContext,
    loaded.session.id,
  );
  return await respondWithStep(
    c,
    context,
    issuerContext,
    refreshed ?? loaded,
    metadata,
  );
}

/** The 404 an unknown, expired or foreign session gets. */
function unknownSession(c: Context<SignetEnvironment>) {
  return c.json(
    {
      error: "invalid_request",
      error_description:
        "This authorization session does not exist or has expired",
    },
    404,
  );
}

/**
 * Loads the session for a handler, or produces the response to send instead.
 *
 * Collapses the preamble every handler shares: an unknown session is a 404, and a
 * step the session is not ready for is answered with the step it *is* on rather than
 * with an error. Returning the response rather than throwing keeps the ordering rule
 * - login, then context, then consent - in one place, where it can be read.
 *
 * The `requireUser` parameter decides whether a session with nobody signed in is
 * handed back to the caller or answered with its current step. The two overloads
 * differ only in what they promise about `endUserId` as a result.
 */
async function loadForInteraction(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
  requireUser: true,
): Promise<AuthenticatedSession | Response>;
async function loadForInteraction(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
  requireUser: false,
): Promise<LoadedSession | Response>;
async function loadForInteraction(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
  requireUser: boolean,
): Promise<LoadedSession | Response> {
  const loaded = await loadSession(
    context,
    issuerContext,
    c.req.param("sessionId") ?? "",
  );
  if (loaded === undefined) {
    return unknownSession(c);
  }
  if (requireUser && loaded.session.endUserId === null) {
    return await respondWithStep(c, context, issuerContext, loaded, metadata);
  }
  return loaded;
}

/**
 * Loads a session for a handler that does not need anybody signed in.
 *
 * A named wrapper rather than a boolean at each call site: `loadForInteraction(c,
 * context, issuerContext, metadata, false)` reads as though `false` were a detail,
 * when it is the difference between a handler that enforces the ordering rule and one
 * that does not.
 */
async function loadSessionForRead(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
): Promise<LoadedSession | Response> {
  return await loadForInteraction(c, context, issuerContext, metadata, false);
}

/** Loads a session for a handler that requires somebody to have signed in. */
async function loadSessionForUser(
  c: Context<SignetEnvironment>,
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  metadata: ReturnType<typeof requestMetadata>,
): Promise<AuthenticatedSession | Response> {
  return await loadForInteraction(c, context, issuerContext, metadata, true);
}

/** Reads the current step and everything needed to render it. */
export function interactionStateHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);
    const loaded = await loadSessionForRead(
      c,
      context,
      issuerContext,
      metadata,
    );
    if (loaded instanceof Response) {
      return loaded;
    }
    return await respondWithStep(c, context, issuerContext, loaded, metadata);
  };
}

/**
 * Attaches the authenticated user, and resolves any context their record supplies.
 *
 * A persona's default context is applied here rather than in the picker, because
 * an authorization that needs no choice should not present one - the point of a
 * seeded persona is that the launch simply works.
 */
async function attachUser(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  loaded: LoadedSession,
  user: EndUser,
): Promise<void> {
  const attached = await attachEndUser(
    context.db,
    issuerContext.scope,
    loaded.session.id,
    user.id,
  );
  // `attachEndUser` matches only while the session has no user, so an absent row
  // means somebody else already authenticated into it. Nothing is overwritten.
  if (attached === undefined) {
    return;
  }

  const requirements = contextRequirements(loaded.requested);
  const resolved: Record<string, string> = {};
  if (requirements.patient) {
    const patient = soleCandidate(contextCandidates(user, "patient"));
    if (patient !== undefined) {
      resolved.patient = patient;
    }
  }
  if (requirements.encounter) {
    const encounter = soleCandidate(contextCandidates(user, "encounter"));
    if (encounter !== undefined) {
      resolved.encounter = encounter;
    }
  }

  const merged: LaunchContext = {
    ...toDefaultLaunchContext(user),
    ...loaded.session.resolvedContext,
    ...resolved,
  };
  const validation = validateLaunchContext(merged);
  if (validation.ok) {
    await setResolvedContext(
      context.db,
      issuerContext.scope,
      loaded.session.id,
      validation.context,
    );
  }
}

/** Authenticates the end user against a local password or a persona. */
export function interactionLoginHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint } = issuerContext;
    const metadata = requestMetadata(c);

    const loaded = await loadSessionForRead(
      c,
      context,
      issuerContext,
      metadata,
    );
    if (loaded instanceof Response) {
      return loaded;
    }
    if (loaded.session.endUserId !== null) {
      // Already authenticated. Report the current step rather than treating a
      // reloaded login page as an error.
      return await respondWithStep(c, context, issuerContext, loaded, metadata);
    }

    const body = await readEndUserCredentials(c);

    const authenticated = await signInEndUser({
      db: context.db,
      scope: issuerContext.scope,
      endpoint,
      credentials: body,
      // Named against the session, so the trail shows which authorization the failed
      // attempt was for and not merely that someone failed to sign in.
      recordFailure: async (reason) => {
        await recordEndUserEvent(context, issuerContext, metadata, {
          action: "end-user.login-failed",
          target: { type: "authorization-session", id: loaded.session.id },
          detail: { reason },
        });
      },
    });
    if (!authenticated.ok) {
      return c.json(authenticated.body, authenticated.status);
    }
    const user = authenticated.user;

    await attachUser(context, issuerContext, loaded, user);

    await recordEndUserEvent(context, issuerContext, metadata, {
      action: "end-user.login",
      target: { type: "authorization-session", id: loaded.session.id },
      detail: { persona: user.isPersona, clientId: loaded.client.clientId },
      endUserId: user.id,
      displayName: user.displayName,
    });

    return await respondAfterAdvance(
      c,
      context,
      issuerContext,
      loaded,
      metadata,
    );
  };
}

/** Records the patient, and optionally the encounter, the user chose. */
export function interactionContextHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const metadata = requestMetadata(c);

    const loaded = await loadSessionForUser(
      c,
      context,
      issuerContext,
      metadata,
    );
    if (loaded instanceof Response) {
      return loaded;
    }

    const user = await getEndUser(
      context.db,
      issuerContext.scope,
      loaded.session.endUserId,
    );
    if (user === undefined) {
      return unknownSession(c);
    }

    const body = (await c.req.json().catch(() => ({}))) as {
      patient?: unknown;
      encounter?: unknown;
    };
    const allowFree = !issuerContext.endpoint.isProduction;
    const chosen: Record<string, string> = {};

    for (const key of ["patient", "encounter"] as const) {
      const value = body[key];
      if (value === undefined || value === null) {
        continue;
      }
      if (
        typeof value !== "string" ||
        !isSelectableContextValue(
          contextCandidates(user, key),
          value,
          allowFree,
        )
      ) {
        return c.json(
          {
            error: "invalid_request",
            error_description: `That ${key} is not one this user may select`,
          },
          400,
        );
      }
      chosen[key] = value;
    }

    const merged: LaunchContext = {
      ...loaded.session.resolvedContext,
      ...chosen,
    };
    const validation = validateLaunchContext(merged);
    if (!validation.ok) {
      return c.json(
        {
          error: "invalid_request",
          error_description: `That context is not valid: ${validation.issues[0]?.message ?? "unknown"}`,
        },
        400,
      );
    }

    await setResolvedContext(
      context.db,
      issuerContext.scope,
      loaded.session.id,
      validation.context,
    );

    return await respondAfterAdvance(
      c,
      context,
      issuerContext,
      loaded,
      metadata,
    );
  };
}

/** Records the user's consent decision, or their refusal. */
export function interactionConsentHandler(context: ServerContext) {
  return async (c: Context<SignetEnvironment>) => {
    const issuerContext = c.get("issuer");
    const { endpoint } = issuerContext;
    const metadata = requestMetadata(c);

    const loaded = await loadSessionForUser(
      c,
      context,
      issuerContext,
      metadata,
    );
    if (loaded instanceof Response) {
      return loaded;
    }

    const body = (await c.req.json().catch(() => ({}))) as {
      approve?: unknown;
    };

    if (body.approve !== true) {
      // A refusal is delivered to the app as `access_denied`, and the session is
      // deleted along with any code it produced. There is nothing to keep: an
      // abandoned authorization has no value to anybody.
      const redirectTo = authorizeErrorRedirect(
        loaded.session.redirectUri,
        "access_denied",
        "The user did not approve this request",
        loaded.session.state ?? undefined,
      );
      // Built before the session is deleted, and complete rather than just the
      // two interesting fields. The page renders a refusal from the same shape it
      // renders every other step from, and a partial body crashed it - leaving
      // the browser on a blank consent page instead of carrying the refusal back
      // to the app, which is a worse outcome than the refusal itself.
      const view = await buildView(context, issuerContext, loaded);

      await deleteAuthorizationSession(
        context.db,
        issuerContext.scope,
        loaded.session.id,
      );
      await recordEndUserEvent(context, issuerContext, metadata, {
        action: "authorize.denied",
        target: { type: "authorization-session", id: loaded.session.id },
        detail: { reason: "user-declined", clientId: loaded.client.clientId },
        endUserId: loaded.session.endUserId,
      });
      return c.json({ ...view, step: "denied", redirectTo });
    }

    await recordSessionConsent(
      context.db,
      issuerContext.scope,
      loaded.session.id,
      context.clock(),
    );

    // Only `remember` mode stores a consent. In `always` mode a stored consent
    // would be an unused row that the management page would nevertheless show the
    // user as a standing permission.
    if (endpoint.consentMode === "remember") {
      await recordConsent(context.db, loaded.clientScope, {
        endUserId: loaded.session.endUserId,
        scope: loaded.session.requestedScopes.join(" "),
        expiresAt: null,
      });
      await recordEndUserEvent(context, issuerContext, metadata, {
        action: "consent.granted",
        target: { type: "client", id: loaded.client.clientId },
        detail: { scopes: loaded.session.requestedScopes },
        endUserId: loaded.session.endUserId,
      });
    }

    await recordEndUserEvent(context, issuerContext, metadata, {
      action: "authorize.consented",
      target: { type: "authorization-session", id: loaded.session.id },
      detail: {
        clientId: loaded.client.clientId,
        scopes: loaded.session.requestedScopes,
      },
      endUserId: loaded.session.endUserId,
    });

    return await respondAfterAdvance(
      c,
      context,
      issuerContext,
      loaded,
      metadata,
    );
  };
}

/**
 * Resumes an authorization after somebody authenticated somewhere else.
 *
 * The one entry point federation needs, and the reason it is here rather than in
 * `federation.ts`: attaching a user, resolving whatever context their record
 * supplies, deriving the next step and issuing the code when nothing is left are
 * all decisions this module already makes, and a second implementation of them
 * would be a second place for the ordering rule to be got wrong.
 *
 * What differs from the login handler is only the answer. A page posting to the
 * interaction API gets JSON and navigates itself; a browser coming back from an
 * identity provider is mid-redirect and has to be sent somewhere, so this returns
 * a URL - the app's redirect URI when the authorization completed outright, and
 * the page for the next step otherwise.
 *
 * @param context - The server's dependencies.
 * @param issuerContext - The endpoint the authorization belongs to.
 * @param sessionId - The authorization session to resume.
 * @param user - The account the upstream sign-in resolved to.
 * @param metadata - Request metadata for the audit trail.
 * @returns Where to send the browser, or undefined when the session has gone -
 *   which the caller must treat as a failed sign-in rather than a redirect.
 */
export async function resumeAuthenticatedSession(
  context: ServerContext,
  issuerContext: ResolvedIssuerContext,
  sessionId: string,
  user: EndUser,
  metadata: ReturnType<typeof requestMetadata>,
): Promise<string | undefined> {
  const loaded = await loadSession(context, issuerContext, sessionId);
  if (loaded === undefined) {
    return undefined;
  }

  await attachUser(context, issuerContext, loaded, user);

  // Re-read rather than reason about the row just written, for the same reason
  // `respondAfterAdvance` does: the step must be derived from committed state.
  const refreshed =
    (await loadSession(context, issuerContext, sessionId)) ?? loaded;
  const view = await buildView(context, issuerContext, refreshed);

  if (view.step === "complete") {
    return await completeAuthorization(
      context,
      issuerContext,
      refreshed,
      metadata,
    );
  }
  if (view.step === "denied") {
    // Not reachable from a successful sign-in - the step is only ever `denied`
    // after somebody declines at the consent screen - but the union includes it,
    // and sending the browser to a page that renders nothing would be worse than
    // handling it here.
    return view.redirectTo;
  }
  return interactionUrl(issuerContext.issuer, view.step, sessionId);
}

/** Re-exported so the router and the pages agree on where a step lives. */

export { interactionUrl } from "./interactionState.js";
