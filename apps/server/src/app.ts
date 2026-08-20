/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { pingDatabase } from "@signet/db";
import { Hono } from "hono";

import { ADMIN_BASE_PATH, createAdminRouter } from "./admin/router.js";
import { serveStaticUi } from "./http/staticFiles.js";
import { createOAuthRouter } from "./oauth/router.js";

import type { ServerContext, SignetEnvironment } from "./context.js";

/**
 * Builds the Signet Hono application.
 *
 * Kept separate from the process entry point so integration tests can drive it
 * through `app.request()` without opening a socket - which is how every grant and
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

  // The admin API is mounted before the OAuth routes. Neither can shadow the
  // other - one lives under `/api/v1` and the other under `/t/{tenant}` - but
  // reading them in this order matches how a request is authenticated: by session
  // or personal access token here, by client credentials there.
  app.route(ADMIN_BASE_PATH, createAdminRouter(context));
  app.route("/", createOAuthRouter(context));

  // Last, and only when a build is present: the UI answers whatever the API and
  // the OAuth endpoints did not claim. Mounting it here rather than first is what
  // keeps an unmatched API route a 404 instead of a page of HTML.
  if (context.config.webRoot !== undefined) {
    app.use("*", serveStaticUi(context.config.webRoot));
  }

  return app;
}
