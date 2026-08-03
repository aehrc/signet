/**
 * Turning textareas into arrays, and back.
 *
 * Redirect URIs, allowed scopes and roles are all lists an operator edits as text
 * and the API takes as an array. Pure and tested, because the interesting cases are
 * the ones a naive `split("\n")` gets wrong: a trailing newline, a line of
 * whitespace, a value pasted with a stray comma, and the difference between an empty
 * list and no list at all.
 */

/**
 * Parses a textarea into a list of values.
 *
 * Splits on newlines *and* commas, because a list pasted from a configuration file
 * arrives either way and an operator should not have to know which this field wants.
 * Blank entries are dropped and each value is trimmed.
 *
 * @param text - The textarea's contents.
 */
export function parseList(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Renders a list back into a textarea's contents.
 *
 * One value per line, which is the form the parser round-trips exactly.
 *
 * @param values - The list to render.
 */
export function formatList(values: readonly string[] | undefined): string {
  return (values ?? []).join("\n");
}

/**
 * Parses a space- or newline-delimited scope string.
 *
 * Scopes are conventionally space-delimited, and a SMART scope can contain a comma
 * inside its search parameters (`patient/Observation.rs?category=a,b`), so splitting
 * on commas here would corrupt one. This is why scopes get their own parser rather
 * than reusing {@link parseList}.
 *
 * @param text - The field's contents.
 */
export function parseScopeList(text: string): string[] {
  return text
    .split(/[\s\n]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * Renders scopes for editing, one per line.
 *
 * @param scopes - The scopes to render.
 */
export function formatScopeList(scopes: readonly string[] | undefined): string {
  return (scopes ?? []).join("\n");
}

/**
 * Reads a positive integer from a text input.
 *
 * Returns undefined for anything that is not one, so a half-typed value leaves the
 * field out of the patch rather than sending `NaN` — which the API would refuse with
 * a message about a type the operator never chose.
 *
 * @param text - The input's contents.
 */
export function parsePositiveInteger(text: string): number | undefined {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) {
    return undefined;
  }
  const value = Number(trimmed);
  return value > 0 ? value : undefined;
}

/**
 * Drops the entries of a patch whose value is unchanged.
 *
 * The admin API's patch routes write only the fields a request names, so sending
 * every field on every save would overwrite a value another operator changed between
 * the page loading and the form being submitted. Comparing against what was loaded
 * makes the request say what this person actually altered.
 *
 * Arrays are compared by their contents in order, since order is significant for
 * redirect URIs and scopes alike.
 *
 * @param next - The values as edited.
 * @param original - The values as loaded.
 */
export function changedFields<T extends Record<string, unknown>>(
  next: T,
  original: Partial<T>,
): Partial<T> {
  const changed: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(next)) {
    if (!isSameValue(value, original[name])) {
      changed[name] = value;
    }
  }
  return changed as Partial<T>;
}

/** Whether two patch values are the same, comparing arrays element-wise. */
function isSameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) {
    return (
      a.length === b.length && a.every((entry, index) => entry === b[index])
    );
  }
  // Null and undefined are deliberately distinguished: the API treats an explicit
  // null as "clear this field" and an absent key as "leave it alone".
  return a === b;
}

/**
 * Drops the fields whose value is blank.
 *
 * Several forms build a request body from optional text inputs, where an untouched field
 * must be absent rather than sent as an empty string — an empty `intent` or `patient` is
 * not the same request as no `intent` at all, and the API's schemas say so. Written once
 * because the conditional-spread version of it, repeated per field, is where a stray
 * empty string gets through.
 *
 * @param values - The candidate fields.
 */
export function withoutBlanks(
  values: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const kept: Record<string, string> = {};
  for (const [name, value] of Object.entries(values)) {
    const trimmed = value?.trim() ?? "";
    if (trimmed.length > 0) {
      kept[name] = trimmed;
    }
  }
  return kept;
}
