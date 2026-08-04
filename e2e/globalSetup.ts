/**
 * Waits for the stack and seeds it, once, before any test runs.
 *
 * The seed is the same script a developer runs by hand (`bun run stack:seed`) and
 * is idempotent, so this is safe against a stack that is already prepared. Running
 * it here means a fresh `stack:up` needs no second command, and a suite cannot
 * fail for want of a fixture in a way that looks like a product bug.
 *
 * Waiting is for Pathling. Everything else in the stack is ready in seconds;
 * Pathling starts a Spark session first, and a suite that began before it was
 * listening would fail its FHIR assertions for a reason that has nothing to do
 * with authorization.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

const SIGNET_PORT = process.env["SIGNET_PORT"] ?? "3000";
const SIGNET =
  process.env["SIGNET_BASE_URL"] ?? `http://localhost:${SIGNET_PORT}`;
const FHIR = process.env["PATHLING_BASE_URL"] ?? "http://localhost:8080/fhir";
const APP = process.env["APP_BASE_URL"] ?? "http://localhost:4000";

/** How long to wait for Pathling, which is the slow one by a wide margin. */
const READY_TIMEOUT_MS = 300_000;

/** Polls a URL until it answers with any status at all. */
async function waitFor(what: string, url: string): Promise<void> {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  for (;;) {
    try {
      const response = await fetch(url);
      // Any answer means the service is listening. A 401 from a FHIR server with
      // authorization on is a *good* sign, not a failure to be retried.
      if (response.status > 0) {
        return;
      }
    } catch {
      // Not up yet.
    }
    if (Date.now() > deadline) {
      throw new Error(
        `${what} did not answer at ${url} within ${String(READY_TIMEOUT_MS / 1000)}s. Is the stack up? Try \`bun run stack:up\`.`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

export default async function globalSetup(): Promise<void> {
  await waitFor("Signet", `${SIGNET}/healthz`);
  await waitFor("the stub SMART app", `${APP}/`);
  await waitFor("Pathling", `${FHIR}/metadata`);

  const { stdout } = await run("bun", ["scripts/seedStack.mjs"], {
    cwd: new URL("..", import.meta.url).pathname,
    env: { ...process.env, SIGNET_BASE_URL: SIGNET },
  });
  process.stdout.write(stdout);
}
