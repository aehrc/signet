/**
 * Serving the built single-page application.
 *
 * One process serves both the API and the UI, which is what makes the session
 * cookie work without CORS and without a second deployment to configure. In
 * development this is absent - Vite serves the UI on its own port and proxies
 * `/api` here - so every path below is dead code in a developer's terminal and
 * load-bearing in production.
 *
 * Two things need care.
 *
 * Path traversal. The requested path is resolved against the web root and the
 * result is required to still be inside it, so `/../../etc/passwd` and every
 * encoding of it resolve to a refusal rather than to a file. Checking the resolved
 * path rather than the raw one is what makes that hold for `..%2f` as well as for
 * `../`.
 *
 * The fallback. A single-page application needs an unknown path to return
 * `index.html` so the router can handle it, but that must not swallow an
 * unmatched API route: answering a mistyped `/api/v1/endpoint` with HTML tells a
 * script that its request succeeded. The fallback therefore applies only to paths
 * that are not claimed by the API or by an endpoint issuer, and only to requests
 * that look like navigation.
 *
 * Author: John Grimes
 */

import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import nodePath from "node:path";
import { Readable } from "node:stream";

import { isEndUserPagePath } from "../oauth/endUserPages.js";

import type { MiddlewareHandler } from "hono";

/** Content types for the extensions a Vite build actually emits. */
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

/** Path prefixes the API and the OAuth endpoints own. Never served from disk. */
const RESERVED_PREFIXES = ["/api/", "/t/", "/healthz", "/readyz"];

/**
 * Whether a request path belongs to something other than the UI.
 *
 * An endpoint's issuer prefix is reserved, because everything under it is an OAuth
 * endpoint - with one documented exception: the five end-user pages, which are part of
 * the UI and are served from the bundle. See `../oauth/endUserPages.js`.
 *
 * @param path - The request path.
 */
export function isReservedPath(path: string): boolean {
  if (isEndUserPagePath(path)) {
    return false;
  }
  return (
    path === "/api" ||
    path === "/t" ||
    RESERVED_PREFIXES.some((prefix) => path.startsWith(prefix))
  );
}

/**
 * Resolves a request path to a file inside the web root, or undefined.
 *
 * Undefined means "not addressable": either the path escapes the root, or it names
 * a directory. Both are refusals rather than fallbacks - a directory listing is
 * not something this server should ever produce.
 *
 * @param root - The absolute web root.
 * @param path - The request path, percent-decoded by the runtime.
 */
export function resolveWithinRoot(
  root: string,
  path: string,
): string | undefined {
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    // A malformed percent-encoding is not a path. Refusing here means the
    // traversal check never has to reason about a half-decoded string.
    return undefined;
  }

  // A NUL byte truncates a path in some system calls, so a value containing one
  // cannot be trusted to address what it appears to.
  if (decoded.includes("\0")) {
    return undefined;
  }

  const candidate = nodePath.resolve(
    nodePath.join(root, nodePath.normalize(decoded)),
  );
  const rootWithSeparator = root.endsWith(nodePath.sep)
    ? root
    : `${root}${nodePath.sep}`;
  if (candidate !== root && !candidate.startsWith(rootWithSeparator)) {
    return undefined;
  }
  return candidate;
}

/**
 * The `Content-Type` for a file, by extension.
 *
 * An unknown extension gets `application/octet-stream` rather than a guess: a
 * mistyped type on a served file is how a script gets executed as something else.
 *
 * @param filePath - The resolved path on disk.
 */
export function contentTypeFor(filePath: string): string {
  return (
    CONTENT_TYPES[nodePath.extname(filePath).toLowerCase()] ??
    "application/octet-stream"
  );
}

/**
 * How long a response may be cached.
 *
 * Vite fingerprints its assets, so anything under `/assets/` is immutable for a
 * year; `index.html` names those assets and must never be cached, or a deployment
 * would serve an old document pointing at files that no longer exist.
 *
 * @param path - The request path.
 */
export function cacheControlFor(path: string): string {
  return path.startsWith("/assets/")
    ? "public, max-age=31536000, immutable"
    : "no-cache";
}

/**
 * Whether an unmatched request should be answered with the application shell.
 *
 * A navigation asks for HTML; a script's `fetch` does not. Serving `index.html` to
 * the second would turn a 404 into a body a caller might try to parse, so only the
 * first gets the fallback.
 *
 * @param method - The request method.
 * @param accept - The `Accept` header, if any.
 */
export function wantsApplicationShell(
  method: string,
  accept: string | undefined,
): boolean {
  return (
    (method === "GET" || method === "HEAD") &&
    accept !== undefined &&
    accept.includes("text/html")
  );
}

/** Reads a file's size, or undefined when it is not a readable file. */
async function fileSize(filePath: string): Promise<number | undefined> {
  try {
    const stats = await stat(filePath);
    return stats.isFile() ? stats.size : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Serves the built UI from `root`, falling back to its `index.html`.
 *
 * @param root - The directory a Vite build produced, from `SIGNET_WEB_ROOT`.
 */
export function serveStaticUi(root: string): MiddlewareHandler {
  const absoluteRoot = nodePath.resolve(root);
  const shell = nodePath.join(absoluteRoot, "index.html");

  return async (c, next) => {
    const requestPath = c.req.path;
    if (isReservedPath(requestPath)) {
      await next();
      return;
    }

    const candidate =
      requestPath === "/"
        ? shell
        : resolveWithinRoot(absoluteRoot, requestPath);
    if (candidate !== undefined) {
      const size = await fileSize(candidate);
      if (size !== undefined) {
        c.header("Content-Type", contentTypeFor(candidate));
        c.header("Cache-Control", cacheControlFor(requestPath));
        c.header("Content-Length", String(size));
        if (c.req.method === "HEAD") {
          return c.body(null, 200);
        }
        return c.body(
          Readable.toWeb(
            createReadStream(candidate),
          ) as unknown as ReadableStream,
        );
      }
    }

    if (wantsApplicationShell(c.req.method, c.req.header("accept"))) {
      const size = await fileSize(shell);
      if (size !== undefined) {
        c.header("Content-Type", "text/html; charset=utf-8");
        c.header("Cache-Control", "no-cache");
        return c.body(
          Readable.toWeb(createReadStream(shell)) as unknown as ReadableStream,
        );
      }
    }

    await next();
    return;
  };
}
