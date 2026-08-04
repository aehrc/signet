/**
 * Author: John Grimes
 */

import type { TemplateValue } from "./types.js";

/**
 * The variables a template may read, as a flat record of roots.
 *
 * Values are `unknown` because a policy may reach into client or user
 * attributes, which Signet does not constrain. Anything a template resolves to
 * is coerced into a {@link TemplateValue} before it can reach a claim, so an
 * exotic value can never leak into a token.
 */
export type TemplateScope = Readonly<Record<string, unknown>>;

/** A filter applied to an interpolated value, with an optional argument. */
export interface TemplateFilter {
  readonly name: string;
  readonly arg?: string;
}

/** Literal text outside any interpolation. */
export interface TemplateLiteralSegment {
  readonly kind: "literal";
  readonly text: string;
}

/** A single `{{ path | filter }}` interpolation. */
export interface TemplateInterpolationSegment {
  readonly kind: "interpolation";
  /** The dotted path, e.g. `context.patient`. Empty when none was written. */
  readonly path: string;
  readonly filters: readonly TemplateFilter[];
  /** The raw text between the braces, for diagnostics. */
  readonly raw: string;
}

/** One piece of a parsed template. */
export type TemplateSegment =
  TemplateLiteralSegment | TemplateInterpolationSegment;

/** A template broken into literal and interpolated segments. */
export interface ParsedTemplate {
  readonly segments: readonly TemplateSegment[];
  /** True when a `{{` was opened and never closed; likely an authoring error. */
  readonly unterminated: boolean;
}

/** Every filter name the template language recognises. */
export const TEMPLATE_FILTER_NAMES: readonly string[] = [
  "join",
  "first",
  "default",
  "lower",
  "upper",
  "stripPrefix",
];

/** Filters that require an argument to do anything meaningful. */
export const TEMPLATE_FILTERS_REQUIRING_ARGUMENT: readonly string[] = [
  "default",
  "stripPrefix",
];

/** Filters that take no argument at all. */
export const TEMPLATE_FILTERS_WITHOUT_ARGUMENT: readonly string[] = [
  "first",
  "lower",
  "upper",
];

/**
 * Path segments that are never resolved, regardless of the data.
 *
 * Walking into `__proto__` or `constructor` would let a policy author read the
 * prototype chain and, through it, reach functions. The language is meant to be
 * data-only, so these are refused outright rather than relying on the shape of
 * whatever object happens to be in scope.
 */
const FORBIDDEN_PATH_SEGMENTS = new Set<string>([
  "__proto__",
  "prototype",
  "constructor",
]);

const OPEN = "{{";
const CLOSE = "}}";

/** Strips a single layer of matching quotes, so `join:", "` keeps its space. */
function unquote(value: string): string {
  const first = value.at(0);
  const last = value.at(-1);
  if (value.length >= 2 && (first === '"' || first === "'") && last === first) {
    return value.slice(1, -1);
  }
  return value.trim();
}

/** Parses one `filter` or `filter:arg` clause. */
function parseFilter(clause: string): TemplateFilter {
  const trimmed = clause.trim();
  const colon = trimmed.indexOf(":");
  if (colon === -1) {
    return { name: trimmed };
  }
  return {
    name: trimmed.slice(0, colon).trim(),
    arg: unquote(trimmed.slice(colon + 1)),
  };
}

/** Parses the inside of a `{{ ... }}` into a path and a filter chain. */
function parseInterpolation(raw: string): TemplateInterpolationSegment {
  const clauses = raw.split("|");
  return {
    kind: "interpolation",
    path: (clauses[0] ?? "").trim(),
    filters: clauses.slice(1).map(parseFilter),
    raw,
  };
}

/**
 * Splits a template into its literal and interpolated segments.
 *
 * Exposed so validation can report authoring errors - unknown filters, missing
 * paths, unbalanced braces - without having to render anything.
 *
 * @param template - The template text.
 */
export function parseTemplate(template: string): ParsedTemplate {
  const segments: TemplateSegment[] = [];
  let index = 0;
  let unterminated = false;

  while (index < template.length) {
    const open = template.indexOf(OPEN, index);
    if (open === -1) {
      segments.push({ kind: "literal", text: template.slice(index) });
      break;
    }
    const close = template.indexOf(CLOSE, open + OPEN.length);
    if (close === -1) {
      // Treat the remainder as literal text so rendering stays total, but flag
      // it: an unclosed brace is almost always a typo.
      unterminated = true;
      segments.push({ kind: "literal", text: template.slice(index) });
      break;
    }
    if (open > index) {
      segments.push({ kind: "literal", text: template.slice(index, open) });
    }
    segments.push(
      parseInterpolation(template.slice(open + OPEN.length, close)),
    );
    index = close + CLOSE.length;
  }

  return { segments, unterminated };
}

/** True when `name` is a filter the language implements. */
export function isTemplateFilterName(name: string): boolean {
  return TEMPLATE_FILTER_NAMES.includes(name);
}

/**
 * Walks a dotted path through the template scope.
 *
 * Only own properties of plain objects and arrays are readable, and a resolved
 * `null` is reported as missing so that a policy never emits `null` by accident
 * - an author who wants a literal `null` writes one directly in `emit`.
 */
function resolvePath(path: string, scope: TemplateScope): unknown {
  let current: unknown = scope;

  for (const segment of path.split(".")) {
    if (segment.length === 0 || FORBIDDEN_PATH_SEGMENTS.has(segment)) {
      return undefined;
    }
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== "object") {
      return undefined;
    }
    const record = current as Record<string, unknown>;
    if (!Object.hasOwn(record, segment)) {
      return undefined;
    }
    current = record[segment];
  }

  return current === null ? undefined : current;
}

/**
 * Coerces a resolved value into text for concatenation.
 *
 * Returns `undefined` for anything with no sensible textual form, so the caller
 * drops the whole template rather than emitting `[object Object]` or `NaN` into
 * a token.
 */
function coerceToString(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "boolean") {
    return String(value);
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? String(value) : undefined;
  }
  if (Array.isArray(value)) {
    return joinValues(value, " ");
  }
  return undefined;
}

/** Joins an array's string-coercible entries, dropping those with no form. */
function joinValues(values: readonly unknown[], separator: string): string {
  const parts: string[] = [];
  for (const entry of values) {
    const text = coerceToString(entry);
    if (text !== undefined) {
      parts.push(text);
    }
  }
  return parts.join(separator);
}

/** The outcome of applying a filter: `ok: false` means the filter is unknown. */
type FilterResult =
  | { readonly ok: true; readonly value: unknown }
  | {
      readonly ok: false;
    };

/** Applies one filter. Every implemented filter is pure and total. */
function applyFilter(filter: TemplateFilter, value: unknown): FilterResult {
  switch (filter.name) {
    case "join": {
      if (value === undefined) {
        return { ok: true, value: undefined };
      }
      const separator = filter.arg ?? " ";
      return {
        ok: true,
        value: Array.isArray(value)
          ? joinValues(value, separator)
          : coerceToString(value),
      };
    }
    case "first": {
      if (Array.isArray(value)) {
        const values = value as readonly unknown[];
        return { ok: true, value: values.length > 0 ? values[0] : undefined };
      }
      return { ok: true, value };
    }
    case "default": {
      return {
        ok: true,
        value: value === undefined ? (filter.arg ?? "") : value,
      };
    }
    case "lower":
    case "upper": {
      const text = coerceToString(value);
      if (text === undefined) {
        return { ok: true, value: undefined };
      }
      return {
        ok: true,
        value:
          filter.name === "lower" ? text.toLowerCase() : text.toUpperCase(),
      };
    }
    case "stripPrefix": {
      const text = coerceToString(value);
      if (text === undefined) {
        return { ok: true, value: undefined };
      }
      const prefix = filter.arg ?? "";
      return {
        ok: true,
        value: text.startsWith(prefix) ? text.slice(prefix.length) : text,
      };
    }
    default: {
      return { ok: false };
    }
  }
}

/**
 * Resolves one interpolation to a raw value.
 *
 * An unknown filter aborts the chain, so a typo cannot be papered over by a
 * later `default:` and silently emit the wrong claim.
 */
function resolveInterpolation(
  segment: TemplateInterpolationSegment,
  scope: TemplateScope,
): unknown {
  let value =
    segment.path.length === 0 ? undefined : resolvePath(segment.path, scope);

  for (const filter of segment.filters) {
    const result = applyFilter(filter, value);
    if (!result.ok) {
      return undefined;
    }
    value = result.value;
  }

  return value;
}

/** Converts each entry of an array, dropping those that resolve to nothing. */
function mapEntries(
  values: readonly unknown[],
  convert: (entry: unknown) => TemplateValue | undefined,
): readonly TemplateValue[] {
  const entries: TemplateValue[] = [];
  for (const value of values) {
    const converted = convert(value);
    if (converted !== undefined) {
      entries.push(converted);
    }
  }
  return entries;
}

/**
 * Converts each own property of an object, dropping those that resolve to
 * nothing.
 *
 * Prototype-polluting keys are skipped here as well as during path resolution,
 * so no claim can carry a `__proto__` property into whatever parses the token.
 */
function mapProperties(
  value: object,
  convert: (entry: unknown) => TemplateValue | undefined,
): Readonly<Record<string, TemplateValue>> {
  const record: Record<string, TemplateValue> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_PATH_SEGMENTS.has(key)) {
      continue;
    }
    const converted = convert(entry);
    if (converted !== undefined) {
      record[key] = converted;
    }
  }
  return record;
}

/**
 * Converts an arbitrary resolved value into a JSON-safe {@link TemplateValue}.
 *
 * Functions, symbols, bigints, non-finite numbers and `null` all become
 * `undefined`, and are then dropped by the caller. This is the boundary that
 * keeps unvetted attribute data from reaching a signed token.
 */
function toTemplateValue(value: unknown): TemplateValue | undefined {
  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (Array.isArray(value)) {
    return mapEntries(value as readonly unknown[], toTemplateValue);
  }
  if (typeof value === "object" && value !== null) {
    return mapProperties(value, toTemplateValue);
  }
  return undefined;
}

/**
 * Renders a template string against a scope.
 *
 * A template that is exactly one interpolation and nothing else yields the raw
 * typed value, so an array stays an array and a boolean stays a boolean - which
 * is what lets a policy emit `need_patient_banner` as a real boolean. Any
 * surrounding literal text switches to string concatenation.
 *
 * Nothing throws. An unresolvable path, an unknown filter, or a value with no
 * textual form yields `undefined`, and the caller drops the claim. There is no
 * expression evaluation of any kind, deliberately: policies are configuration,
 * not code.
 *
 * @param template - The template text.
 * @param scope - The variables in scope.
 * @returns The rendered value, or `undefined` when it cannot be resolved.
 */
export function renderTemplate(
  template: string,
  scope: TemplateScope,
): TemplateValue | undefined {
  const { segments } = parseTemplate(template);

  const only = segments.length === 1 ? segments[0] : undefined;
  if (only !== undefined && only.kind === "interpolation") {
    return toTemplateValue(resolveInterpolation(only, scope));
  }

  let text = "";
  for (const segment of segments) {
    if (segment.kind === "literal") {
      text += segment.text;
      continue;
    }
    const rendered = coerceToString(resolveInterpolation(segment, scope));
    // One unresolvable part poisons the whole string: emitting
    // `Patient/undefined` would be worse than emitting nothing.
    if (rendered === undefined) {
      return undefined;
    }
    text += rendered;
  }
  return text;
}

/**
 * Renders every template string inside a claim value, recursively.
 *
 * Only strings are treated as templates. Numbers, booleans and `null` are
 * literals and pass through untouched, so a policy can emit a genuine `null`
 * when it means to. Array entries and object properties that resolve to
 * `undefined` are dropped.
 *
 * @param value - The literal-or-template value from a rule's `emit`.
 * @param scope - The variables in scope.
 * @returns The rendered value, or `undefined` when the claim should be dropped.
 */
export function renderTemplateValue(
  value: TemplateValue,
  scope: TemplateScope,
): TemplateValue | undefined {
  if (typeof value === "string") {
    return renderTemplate(value, scope);
  }
  const render = (entry: unknown): TemplateValue | undefined =>
    renderTemplateValue(entry as TemplateValue, scope);
  if (Array.isArray(value)) {
    return mapEntries(value as readonly TemplateValue[], render);
  }
  if (typeof value === "object" && value !== null) {
    return mapProperties(value, render);
  }
  return value;
}
