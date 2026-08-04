/**
 * CORS for the endpoints a browser-based SMART app calls directly.
 *
 * A public SMART app running in a browser fetches the discovery document, the
 * JWKS and the token endpoint from JavaScript, so those three must answer
 * cross-origin requests or a public client cannot complete a launch at all. The
 * authorization endpoint is deliberately *not* in that set: it is navigated to,
 * never fetched, and adding CORS headers to it would only help a script read a
 * response it has no business reading.
 *
 * `Access-Control-Allow-Origin: *` is correct here and is not a weakening. These
 * responses carry no cookie-authenticated data: discovery and JWKS are public
 * documents, and the token endpoint authenticates with a code and a PKCE verifier
 * that the caller must already hold. Credentials are explicitly *not* allowed,
 * which is what keeps a browser from attaching the operator's console session
 * cookie to a cross-origin token request.
 *
 * @see https://hl7.org/fhir/smart-app-launch/app-launch.html#considerations-for-cross-origin-requests
 *
 * Author: John Grimes
 */

import type { MiddlewareHandler } from "hono";

/** Request headers a SMART app legitimately sends to these endpoints. */
const ALLOWED_HEADERS = ["authorization", "content-type", "accept"].join(", ");

/** How long a browser may cache the preflight result, in seconds. */
const PREFLIGHT_MAX_AGE = "600";

/**
 * Adds permissive CORS headers, and answers preflight requests.
 *
 * Mounted only on the routes named in the module header.
 *
 * @param methods - The methods to advertise, e.g. `["POST", "OPTIONS"]`.
 */
export function publicCors(methods: readonly string[]): MiddlewareHandler {
  const allowMethods = [...methods, "OPTIONS"].join(", ");

  return async (c, next) => {
    c.header("Access-Control-Allow-Origin", "*");
    c.header("Access-Control-Allow-Methods", allowMethods);
    c.header("Access-Control-Allow-Headers", ALLOWED_HEADERS);
    c.header("Access-Control-Max-Age", PREFLIGHT_MAX_AGE);
    // Deliberately absent: `Access-Control-Allow-Credentials`. See the header.

    if (c.req.method === "OPTIONS") {
      return c.body(null, 204);
    }

    await next();
    return;
  };
}
