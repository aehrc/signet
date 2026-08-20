/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Unwrapping the admin API's envelopes.
 *
 * Every collection response is an object with one field - `{ endpoints: [...] }`,
 * `{ client: {...} }` - rather than a bare array or a bare row. That is deliberate on
 * the server's side: an envelope leaves room to add a field later without changing the
 * shape a client already parses.
 *
 * It does mean every caller would otherwise write `(await get(...)).endpoints`, which
 * is both noisy and awkward. These two helpers do the unwrapping once.
 *
 * Author: John Grimes
 */

import { get, patch, post } from "./client.js";

/**
 * Reads a resource and returns the field the API wrapped it in.
 *
 * @param path - The admin API path.
 * @param field - The envelope's single field name.
 * @param signal - Abort signal, supplied by TanStack Query.
 */
export async function getField<Field extends string, Value>(
  path: string,
  field: Field,
  signal?: AbortSignal,
): Promise<Value> {
  const body = await get<Record<Field, Value>>(path, signal);
  return body[field];
}

/**
 * Posts to a resource and returns the field the API wrapped the result in.
 *
 * @param path - The admin API path.
 * @param field - The envelope's single field name.
 * @param body - The request body, if there is one.
 */
export async function postField<Field extends string, Value>(
  path: string,
  field: Field,
  body?: unknown,
): Promise<Value> {
  const response = await post<Record<Field, Value>>(path, body);
  return response[field];
}

/**
 * Patches a resource and returns the field the API wrapped the result in.
 *
 * @param path - The admin API path.
 * @param field - The envelope's single field name.
 * @param body - The patch. Only the fields it names are written.
 */
export async function patchField<Field extends string, Value>(
  path: string,
  field: Field,
  body: unknown,
): Promise<Value> {
  const response = await patch<Record<Field, Value>>(path, body);
  return response[field];
}
