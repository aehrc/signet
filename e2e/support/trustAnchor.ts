/**
 * The stand-in trust anchor, addressed so that a containerised Signet can reach it.
 *
 * The anchor itself is the one the unit and integration suites use -
 * `apps/server/src/test/trustAnchor.ts` - and it is imported rather than copied so
 * that a statement minted here is minted by exactly the code the rest of the suite
 * verifies against. What this file adds is one thing: an address.
 *
 * The anchor runs in the Playwright process, which is on the host, and Signet runs
 * in a container. A socket bound to the host's `127.0.0.1` is not one the container
 * can open, and the compose network's DNS has no name for the host - so the socket
 * binds every address and calls itself `host.docker.internal`, which is the name
 * Docker Desktop defines and which `deploy/compose/docker-compose.yml` adds for
 * Linux. Signet's outbound guard would refuse the private address that name
 * resolves to; the stack sets `SIGNET_ALLOW_PRIVATE_OUTBOUND_FETCHES`, which is the
 * same allowance every other hop inside the stack already needs.
 *
 * The port is ephemeral, so nothing has to be published or reserved: the container
 * dials out to the host, rather than the host publishing another listener.
 *
 * Author: John Grimes
 */

import { startTrustAnchor } from "../../apps/server/src/test/trustAnchor.js";

import type { TrustAnchor } from "../../apps/server/src/test/trustAnchor.js";

/**
 * The name Signet reaches the host by.
 *
 * Overridable for a stack that is not this compose stack - a Signet run from
 * source on the host reaches the anchor at `127.0.0.1`, and a container runtime
 * that names the host differently can say so.
 */
export const ANCHOR_HOST =
  process.env["SIGNET_E2E_ANCHOR_HOST"] ?? "host.docker.internal";

/**
 * Starts the anchor on an address the stack's Signet can fetch keys from.
 *
 * @param issuer - The issuer identifier its statements and tickets claim. Defaults
 *   to the anchor's own advertised origin, as a real anchor publishing its keys
 *   under its issuer would.
 * @returns The running anchor. Close it, or the socket outlives the suite.
 * @example
 * ```ts
 * const anchor = await startStackTrustAnchor();
 * const statement = await anchor.mintStatement({ claims: { client_name: "App" } });
 * await anchor.close();
 * ```
 */
export async function startStackTrustAnchor(
  issuer?: string,
): Promise<TrustAnchor> {
  return await startTrustAnchor({
    ...(issuer === undefined ? {} : { issuer }),
    listener: { hostname: "0.0.0.0", advertisedHost: ANCHOR_HOST },
  });
}
