import { pingDatabase } from "@signet/db";
import { Hono } from "hono";

import { createOAuthRouter } from "./oauth/router.js";

import type { ServerContext, SignetEnvironment } from "./context.js";

/**
 * Builds the Signet Hono application.
 *
 * Kept separate from the process entry point so integration tests can drive it
 * through `app.request()` without opening a socket — which is how every grant and
 * every rejection path is exercised against a real database.
 *
 * @param context - The server's dependencies. Passed in rather than constructed
 *   here, so a test can substitute a throwaway database and a fixed clock.
 */
export function createApp(context: ServerContext): Hono<SignetEnvironment> {
  const app = new Hono<SignetEnvironment>();

  // Liveness answers from the process alone. A pod whose database is down is still
  // alive, and restarting it would neither fix the database nor help anybody.
  app.get("/healthz", (c) => c.json({ status: "ok" }));

  // Readiness does check the database: a pod that cannot reach Postgres can serve no
  // OAuth request, and should leave the load balancer rather than answering every
  // request with a 500.
  app.get("/readyz", async (c) => {
    try {
      await pingDatabase(context.db);
      return c.json({ status: "ok" });
    } catch {
      return c.json({ status: "unavailable", database: "unreachable" }, 503);
    }
  });

  app.route("/", createOAuthRouter(context));

  return app;
}
