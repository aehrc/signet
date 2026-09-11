/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Request metadata for the audit trail.
 *
 * Every authorization decision is audited with the address and user agent it came
 * from, and neither is trustworthy. That is not a reason to omit them - an audit
 * log records what was claimed as well as what happened - but it is a reason to
 * be careful about how they are read.
 *
 * `X-Forwarded-For` is a list, and every entry a client can write is one the
 * client chose: a client sending `X-Forwarded-For: 1.2.3.4` and then being
 * proxied produces `1.2.3.4, <real address>`. Only the entries appended by the
 * proxies the deployment declares trusted carry provenance, so the address is
 * read from exactly `trustedProxyCount` entries back - and when the chain is
 * shorter than that, or no proxy is trusted, the socket address is used
 * instead. Fail closed: a deployment that says nothing about its proxies gets
 * the socket address, not whatever the caller wrote.
 *
 * Author: John Grimes
 */

import type { ServerContext } from "../context.js";
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
 * Reads the client address, trusting `X-Forwarded-For` only as far as declared.
 *
 * @param forwardedFor - The raw `X-Forwarded-For` header.
 * @param remoteAddress - The socket's peer address, when the runtime exposes one.
 * @param trustedProxyCount - How many proxies append to the header. See the
 *   module header.
 */
export function clientAddress(
  forwardedFor: string | undefined,
  remoteAddress: string | undefined,
  trustedProxyCount: number,
): string | undefined {
  const socket = sanitise(remoteAddress, 64);
  if (trustedProxyCount < 1) {
    return socket;
  }
  const cleaned = sanitise(forwardedFor, 1024);
  if (cleaned === undefined) {
    return socket;
  }
  const entries = cleaned
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  // The entry the first trusted proxy observed of the caller. A chain shorter
  // than the declared count means the caller wrote what there is.
  if (entries.length < trustedProxyCount) {
    return socket;
  }
  const chosen = entries.at(-trustedProxyCount);
  return chosen ?? socket;
}

/**
 * Reads the socket's peer address, when the runtime exposes one.
 *
 * `@hono/node-server` hangs the underlying request off `c.env`, a shape Hono's
 * types do not declare; the structure is fixed by that package, which is the
 * reason the one cast below is trusted. Absent in `app.request()` tests, where
 * there is no socket, and the absence is correct rather than a gap.
 *
 * @param c - The Hono request context.
 */
function socketAddress(c: Context): string | undefined {
  if (c.env === undefined || typeof c.env !== "object") {
    return undefined;
  }
  const nodeEnv = c.env as {
    incoming?: { socket?: { remoteAddress?: string } };
  };
  return nodeEnv.incoming?.socket?.remoteAddress;
}

/**
 * Reads the client address a request came from.
 *
 * The rate limiter keys on this, so it needs the address without the rest of the
 * metadata.
 *
 * @param c - The Hono request context.
 * @param trustedProxyCount - How many proxies append to `X-Forwarded-For`. See
 *   the module header.
 */
export function requestAddress(
  c: Context,
  trustedProxyCount: number,
): string | undefined {
  return clientAddress(
    c.req.header("x-forwarded-for"),
    socketAddress(c),
    trustedProxyCount,
  );
}

/**
 * Collects the audit metadata for a request.
 *
 * @param context - The server's dependencies; the trusted-proxy count is read
 *   from its configuration. See the module header.
 * @param c - The Hono request context.
 */
export function requestMetadata(
  context: ServerContext,
  c: Context,
): RequestMetadata {
  const ip = requestAddress(c, context.config.trustedProxyCount);
  const userAgent = sanitise(c.req.header("user-agent"), MAX_USER_AGENT_LENGTH);

  return {
    ...(ip === undefined ? {} : { ip }),
    ...(userAgent === undefined ? {} : { userAgent }),
  };
}
