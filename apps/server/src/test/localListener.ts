/**
 * A request handler on a real loopback socket, for the suites that need one.
 *
 * Two of the stubs here - an upstream identity provider and a trust anchor -
 * exist because mocking `fetch` would test the wrong thing. What has to hold is
 * that Signet, handed a counterparty that behaves like a counterparty, completes
 * the exchange: a document served over HTTP, a JWKS whose keys actually verify,
 * a socket that can be made to fail. A mock lets every one of those be subtly
 * wrong while the suite goes green.
 *
 * Both bind port zero on `127.0.0.1`, which is exactly what the outbound-fetch
 * guard is built to refuse - so a suite using either must construct its stack
 * with `allowPrivateOutboundFetches`. That is not an inconvenience to route
 * around: it is the guard proving it works before the test has asserted
 * anything.
 *
 * Author: John Grimes
 */

import { serve } from "@hono/node-server";

import type { ServerType } from "@hono/node-server";

/** A stub listening on an ephemeral loopback port. */
export interface LocalListener {
  /** `http://127.0.0.1:{port}`, with no trailing slash. */
  readonly origin: string;
  readonly close: () => Promise<void>;
}

/** Where a stub binds, and what it calls itself. */
export interface LocalListenerOptions {
  /**
   * The address to bind. Loopback unless something outside the host has to reach
   * it, which for this repository means the end-to-end suite: Signet runs in a
   * container there and a socket bound to the host's loopback is not a socket a
   * container can open.
   */
  readonly hostname?: string;
  /**
   * The host that goes into {@link LocalListener.origin}, where that differs from
   * the bind address.
   *
   * They differ for exactly one reason: the name a caller reaches this listener
   * by is not a name the listener can bind. `host.docker.internal` resolves
   * inside a container and nowhere else, so the socket binds every address and
   * advertises the one the container can use.
   */
  readonly advertisedHost?: string;
}

/**
 * Starts a request handler on an ephemeral port.
 *
 * The handler is given the origin as well as the request, because a stub usually
 * has to publish absolute URLs to itself - a discovery document's `jwks_uri`, an
 * issuer identifier - and the origin is not known until the socket is bound.
 *
 * @param handle - Answers each request. Receives the bound origin.
 * @param options - Where to bind, and what to call it. Loopback by default.
 * @returns The bound origin and a function that stops listening.
 * @throws {Error} When the socket binds no port, which would otherwise produce a
 *   stub whose origin is the empty string and whose every fetch fails obscurely.
 * @example
 * ```ts
 * const listener = await startLocalListener(async (request, origin) =>
 *   jsonResponse({ issuer: origin }),
 * );
 * ```
 */
export async function startLocalListener(
  handle: (request: Request, origin: string) => Promise<Response>,
  options: LocalListenerOptions = {},
): Promise<LocalListener> {
  const hostname = options.hostname ?? "127.0.0.1";
  let origin = "";
  // Port zero, so parallel suites cannot collide on a fixed one. The port is only
  // known once the socket is bound, which is what the callback is waited on for -
  // reading `address()` synchronously returns null and produced a stub whose
  // origin was the empty string.
  const server = await new Promise<ServerType>((resolve) => {
    const started: ServerType = serve(
      {
        fetch: async (request: Request) => await handle(request, origin),
        hostname,
        port: 0,
      },
      () => {
        resolve(started);
      },
    );
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("the stub listener did not bind a port");
  }
  origin = `http://${options.advertisedHost ?? hostname}:${String(address.port)}`;

  return {
    origin,
    close: async () =>
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined || error === null) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
}

/**
 * A JSON response, as every stub here answers.
 *
 * @param body - Serialised as the response body.
 * @param status - HTTP status, defaulting to 200.
 * @returns The response.
 */
export function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "content-type": "application/json" },
  });
}
