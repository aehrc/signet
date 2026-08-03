import { Hono } from "hono";

/**
 * Builds the Signet Hono application.
 *
 * Kept separate from the process entry point so integration tests can drive it
 * through `app.request()` without opening a socket.
 */
export function createApp(): Hono {
  const app = new Hono();

  app.get("/healthz", (c) => c.json({ status: "ok" }));

  // Readiness will additionally check database reachability once the data layer
  // lands in phase 2.
  app.get("/readyz", (c) => c.json({ status: "ok" }));

  return app;
}
