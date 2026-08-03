/**
 * Request metadata for the audit trail.
 *
 * Every authorization decision is audited with the address and user agent it came
 * from, and neither is trustworthy. That is not a reason to omit them — an audit
 * log records what was claimed as well as what happened — but it is a reason to
 * be careful about how they are read.
 *
 * `X-Forwarded-For` is a list, and the entries an untrusted client can write are
 * the *leftmost* ones: a client sending `X-Forwarded-For: 1.2.3.4` and then being
 * proxied produces `1.2.3.4, <real address>`. Taking the first entry therefore
 * records whatever the caller asked to be recorded. Signet takes the last entry
 * instead, which is the address the nearest trusted proxy observed — the most
 * specific value that is not purely caller-controlled. A deployment that runs
 * several proxies in series will want to count back further, which is a
 * configuration question rather than a code one, and is noted in the deployment
 * documentation rather than guessed at here.
 */

import type { Context } from "hono";

/** C0 controls and DEL, which make a header unsafe to store in a log. */
// eslint-disable-next-line no-control-regex -- matching control characters is the point.
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/g;

/** Longest user agent retained. Beyond this the value is padding, not evidence. */
const MAX_USER_AGENT_LENGTH = 512;

/** What the audit trail records about where a request came from. */
export interface RequestMetadata {
  readonly ip?: string;
  readonly userAgent?: string;
}

/**
 * Strips control characters and clamps a header value.
 *
 * Both matter for a value that ends up in a log: a newline in a stored header is
 * how a forged log entry gets written.
 */
function sanitise(
  value: string | undefined,
  maxLength: number,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const cleaned = value.replaceAll(CONTROL_CHARACTERS, "").trim();
  return cleaned.length === 0 ? undefined : cleaned.slice(0, maxLength);
}

/**
 * Reads the client address a proxy chain reports.
 *
 * @param forwardedFor - The raw `X-Forwarded-For` header.
 * @param remoteAddress - The socket's peer address, when the runtime exposes one.
 */
export function clientAddress(
  forwardedFor: string | undefined,
  remoteAddress: string | undefined,
): string | undefined {
  const cleaned = sanitise(forwardedFor, 1024);
  if (cleaned === undefined) {
    return sanitise(remoteAddress, 64);
  }

  // The last entry, not the first. See the module header.
  const entries = cleaned
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  return entries.at(-1) ?? sanitise(remoteAddress, 64);
}

/**
 * Collects the audit metadata for a request.
 *
 * @param c - The Hono request context.
 */
export function requestMetadata(c: Context): RequestMetadata {
  const ip = clientAddress(
    c.req.header("x-forwarded-for"),
    // Present under `@hono/node-server`; absent in `app.request()` tests, where
    // there is no socket, and the absence is correct rather than a gap.
    c.env !== undefined && typeof c.env === "object" && "incoming" in c.env
      ? (c.env as { incoming?: { socket?: { remoteAddress?: string } } })
          .incoming?.socket?.remoteAddress
      : undefined,
  );
  const userAgent = sanitise(c.req.header("user-agent"), MAX_USER_AGENT_LENGTH);

  return {
    ...(ip === undefined ? {} : { ip }),
    ...(userAgent === undefined ? {} : { userAgent }),
  };
}
