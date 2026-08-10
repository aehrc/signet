/**
 * Waits for the stack, and re-seeds it, before any test runs.
 *
 * The compose stack seeds itself: Pathling resolves its issuer eagerly at
 * startup, so the `seed` service has to run between bootstrap and Pathling or
 * Pathling never starts. By the time this runs, the fixtures are already there.
 *
 * It is repeated here anyway, because the suite must also work against a stack
 * this repository did not bring up - a developer running Signet from source, or a
 * long-lived stack whose seed predates a change to the script. The seed is
 * idempotent, so the repeat costs a few requests and removes a whole class of
 * confusing failure where a missing fixture looks like a product bug.
 *
 * Waiting is for Pathling. Everything else in the stack is ready in seconds;
 * Pathling starts a Spark session first, and a suite that began before it was
 * listening would fail its FHIR assertions for a reason that has nothing to do
 * with authorization.
 *
 * Author: John Grimes
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { resolveStackUrls } from "./src/stackUrls.js";
import { SEED } from "./support/stack.js";

const run = promisify(execFile);

const { signet: SIGNET, fhir: FHIR, app: APP } = resolveStackUrls(process.env);

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

  // The stack's own credentials, set last so a developer's `SIGNET_BOOTSTRAP_*`
  // cannot reach the seed. See `support/stack.ts` for why that matters.
  //
  // The three URLs are passed explicitly rather than left to the script's own
  // defaults, so that what the seed *stores* is what this suite will *ask for*
  // even if the two ever disagree about how to read the environment.
  const { stdout } = await run("bun", ["scripts/seedStack.mjs"], {
    cwd: new URL("..", import.meta.url).pathname,
    env: {
      ...process.env,
      SIGNET_BASE_URL: SIGNET,
      SIGNET_SEED_FHIR_BASE: FHIR,
      SIGNET_SEED_APP_ORIGIN: APP,
      SIGNET_BOOTSTRAP_EMAIL: SEED.adminEmail,
      SIGNET_BOOTSTRAP_PASSWORD: SEED.adminPassword,
    },
  });
  process.stdout.write(stdout);
}
