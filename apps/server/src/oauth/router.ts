/**
 * Every route that lives under an endpoint's issuer.
 *
 * The mount path and the issuer identifier are derived from the same configured
 * public URL, so what the discovery document advertises and what the server serves
 * cannot diverge — see `./issuer.ts`.
 *
 * CORS is applied selectively. A browser-based public SMART app fetches the
 * discovery documents, the JWKS and the token endpoint from JavaScript, so those
 * must answer cross-origin. `/authorize` is navigated to rather than fetched, and
 * the interaction API is called by Signet's own pages from the same origin;
 * neither gets CORS headers, because a script that could read those responses would
 * be able to read an authorization in progress.
 */

import { Hono } from "hono";

import { authorizeHandler } from "./authorize.js";
import {
  clientRegistrationHandler,
  clientRequestStatusHandler,
  submitClientRequestHandler,
} from "./developerPortal.js";
import {
  jwksHandler,
  openIdConfigurationHandler,
  smartConfigurationHandler,
} from "./discovery.js";
import {
  federationCallbackHandler,
  federationStartHandler,
} from "./federation.js";
import {
  interactionConsentHandler,
  interactionContextHandler,
  interactionLoginHandler,
  interactionStateHandler,
} from "./interaction.js";
import { introspectHandler } from "./introspect.js";
import { ISSUER_PATH_PREFIX, withIssuer } from "./issuer.js";
import { launchContextHandler } from "./launchContextEndpoint.js";
import {
  manageAuthorizationsHandler,
  manageRevokeHandler,
  manageSignInHandler,
  manageSignOutHandler,
} from "./manage.js";
import { revokeHandler } from "./revoke.js";
import { tokenHandler } from "./token.js";
import { userinfoHandler } from "./userinfo.js";
import { publicCors } from "../http/cors.js";
import { rateLimit } from "../http/rateLimit.js";

import type { ServerContext, SignetEnvironment } from "../context.js";

/**
 * Builds the router for `/t/:tenantSlug/e/:endpointSlug/*`.
 *
 * @param context - The server's dependencies.
 */
export function createOAuthRouter(
  context: ServerContext,
): Hono<SignetEnvironment> {
  const router = new Hono<SignetEnvironment>();

  // Every route below resolves the endpoint first, so no handler can be reached
  // without an `EndpointScope` — which is what stops any of them from querying
  // another tenant's rows.
  router.use(`${ISSUER_PATH_PREFIX}/*`, withIssuer(context));

  const path = (suffix: string) => `${ISSUER_PATH_PREFIX}${suffix}`;

  // Discovery and keys: public, cacheable, cross-origin readable.
  const readOnlyCors = publicCors(["GET"]);
  router.use(path("/.well-known/*"), readOnlyCors);
  router.use(path("/jwks"), readOnlyCors);
  router.get(
    path("/.well-known/smart-configuration"),
    smartConfigurationHandler,
  );
  router.get(
    path("/.well-known/openid-configuration"),
    openIdConfigurationHandler,
  );
  router.get(path("/jwks"), jwksHandler(context));

  // The authorization endpoint. `POST` is refused by the handler on endpoints that
  // do not advertise `authorize-post`, rather than being unrouted, so the refusal
  // can explain itself.
  // Limited by client address: every request writes a session row, and it is
  // reachable with no credential at all. See `../http/rateLimit.js`.
  router.use(
    path("/authorize"),
    rateLimit("authorize", context.clock, context.rateLimits),
  );
  router.get(path("/authorize"), authorizeHandler(context));
  router.post(path("/authorize"), authorizeHandler(context));

  const tokenCors = publicCors(["POST"]);
  router.use(path("/token"), tokenCors);
  router.use(path("/introspect"), tokenCors);
  router.post(
    path("/token"),
    rateLimit("token", context.clock, context.rateLimits),
    tokenHandler(context),
  );
  router.post(path("/introspect"), introspectHandler(context));
  router.post(path("/revoke"), revokeHandler(context));
  router.get(path("/userinfo"), userinfoHandler(context));
  router.post(path("/launch-context"), launchContextHandler(context));

  // The interaction API, called by the end-user pages on the same origin.
  router.get(path("/interaction/:sessionId"), interactionStateHandler(context));
  // The two surfaces that check a password. Ten a minute per address: see the
  // limit's own documentation for why that is the number.
  router.post(
    path("/interaction/:sessionId/login"),
    rateLimit("signIn", context.clock, context.rateLimits),
    interactionLoginHandler(context),
  );
  router.post(
    path("/interaction/:sessionId/context"),
    interactionContextHandler(context),
  );
  router.post(
    path("/interaction/:sessionId/consent"),
    interactionConsentHandler(context),
  );

  // The upstream federation round trip, for an endpoint in `oidc` auth mode. Both are
  // browser navigations rather than fetches, so neither gets CORS headers.
  router.get(path("/federation/start"), federationStartHandler(context));
  router.get(path("/federation/callback"), federationCallbackHandler(context));

  // The management endpoint, which SMART advertises as `management_endpoint`. Its own
  // session, because an end user reviewing their authorizations is not in the middle of
  // one — see `./manage.js`.
  // Signing in only: signing out must not be refused because somebody else on
  // the same address was guessing passwords.
  router.post(
    path("/manage/session"),
    rateLimit("signIn", context.clock, context.rateLimits),
    manageSignInHandler(context),
  );
  router.delete(path("/manage/session"), manageSignOutHandler(context));
  router.get(
    path("/manage/authorizations"),
    manageAuthorizationsHandler(context),
  );
  router.post(path("/manage/revoke"), manageRevokeHandler(context));

  // The developer portal. Off unless the endpoint accepts self-serve requests.
  router.post(path("/apps/requests"), submitClientRequestHandler(context));
  router.get(
    path("/apps/requests/:requestId"),
    clientRequestStatusHandler(context),
  );
  router.get(
    path("/apps/registration/:clientId"),
    clientRegistrationHandler(context),
  );

  return router;
}
