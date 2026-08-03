/**
 * The one place the console talks to the server.
 *
 * Every request goes through here, which is what makes three properties true
 * everywhere rather than in most places: the session cookie is always sent, a
 * refusal always arrives as an {@link ApiError} carrying the server's own message
 * and field-level issues, and no caller has to remember to check `response.ok`.
 *
 * There is no bearer token here. The console authenticates with the httpOnly
 * session cookie, which JavaScript cannot read — that is the point of it — so
 * `credentials: "same-origin"` is the whole of the credential handling.
 */

import { toApiError } from "./errors.js";

/** What a request may carry. */
export interface RequestOptions {
  readonly method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  /** Serialised as JSON. Omit for a request with no body. */
  readonly body?: unknown;
  /** Aborts the request; supplied by TanStack Query. */
  readonly signal?: AbortSignal;
}

/**
 * Makes a request and returns its parsed body.
 *
 * @param path - An admin API path, from `./paths.js`.
 * @param options - The method, body and abort signal.
 * @throws {ApiError} For any non-2xx response, carrying the server's message.
 * @returns The parsed JSON body, or undefined for a `204`.
 */
export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const response = await fetch(path, {
    method: options.method ?? "GET",
    // Same-origin rather than `include`: the API is served by the same process as
    // this bundle, and a cross-origin credentialed request is not something the
    // console should be able to make by accident.
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      ...(options.body === undefined
        ? {}
        : { "content-type": "application/json" }),
    },
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });

  if (response.status === 204) {
    return undefined as T;
  }

  // Parsed before the status is inspected, because a refusal's body is where the
  // message and the field issues are. A body that is not JSON at all yields
  // undefined and `toApiError` falls back to describing the status.
  const body: unknown = await response.json().catch(() => {});

  if (!response.ok) {
    throw toApiError(response.status, body);
  }
  return body as T;
}

/** Reads a resource. */
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return await request<T>(path, {
    ...(signal === undefined ? {} : { signal }),
  });
}

/** Creates a resource, or performs an action on one. */
export async function post<T>(path: string, body?: unknown): Promise<T> {
  return await request<T>(path, {
    method: "POST",
    ...(body === undefined ? {} : { body }),
  });
}

/** Edits a resource. */
export async function patch<T>(path: string, body: unknown): Promise<T> {
  return await request<T>(path, { method: "PATCH", body });
}

/** Replaces or upserts a resource. */
export async function put<T>(path: string, body: unknown): Promise<T> {
  return await request<T>(path, { method: "PUT", body });
}

/** Deletes a resource. */
export async function remove(path: string): Promise<void> {
  await request<void>(path, { method: "DELETE" });
}
