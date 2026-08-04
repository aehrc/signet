/**
 * Author: John Grimes
 */

import { parseScopePattern } from "./pattern.js";
import {
  isTemplateFilterName,
  parseTemplate,
  TEMPLATE_FILTERS_REQUIRING_ARGUMENT,
  TEMPLATE_FILTERS_WITHOUT_ARGUMENT,
} from "./template.js";
import { formatScope, parseScope } from "../scopes/index.js";

import type { PolicyDocument, PolicyIssue, PolicyValidation } from "./types.js";

const TOP_LEVEL_KEYS: readonly string[] = [
  "version",
  "scopeGrants",
  "claimRules",
  "scopeMappings",
  "contextRules",
  "defaults",
];

const METADATA_KEYS: readonly string[] = ["id", "description", "enabled"];

const GRANT_KEYS: readonly string[] = [
  ...METADATA_KEYS,
  "match",
  "allow",
  "narrow",
  "requireContext",
  "requireUserRole",
  "grantTypes",
  "clientTypes",
];

const CLAIM_KEYS: readonly string[] = [...METADATA_KEYS, "when", "emit"];

const MAPPING_KEYS: readonly string[] = [
  ...METADATA_KEYS,
  "when",
  "forEachScope",
  "appendTo",
  "values",
];

const CONDITION_KEYS: readonly string[] = [
  "always",
  "scope",
  "context",
  "grantTypes",
  "clientTypes",
  "userRole",
  "hasUser",
];

const DEFAULTS_KEYS: readonly string[] = ["accessTokenTtl", "refreshTokenTtl"];

const GRANT_TYPES: readonly string[] = [
  "authorization_code",
  "client_credentials",
  "refresh_token",
];

const CLIENT_TYPES: readonly string[] = [
  "public",
  "confidential-symmetric",
  "confidential-asymmetric",
];

const REQUIRE_CONTEXT_KEYS: readonly string[] = ["patient", "encounter"];

const LAUNCH_CONTEXT_KEYS: readonly string[] = [
  "patient",
  "encounter",
  "fhirContext",
  "intent",
  "tenant",
  "needPatientBanner",
  "smartStyleUrl",
];

/** A path segment in a template: word characters and dashes only. */
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;

/** True for a plain object, which every node of a policy document must be. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Accumulates issues while walking the document. */
interface Context {
  readonly issues: PolicyIssue[];
  /** Rule ids seen so far, mapped to where they were first used. */
  readonly ids: Map<string, string>;
}

/** Records one issue. */
function add(ctx: Context, path: string, message: string): void {
  ctx.issues.push({ path, message });
}

/** Reports any key the schema does not define. */
function checkKeys(
  ctx: Context,
  record: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      add(ctx, path === "" ? key : `${path}.${key}`, `Unknown key "${key}"`);
    }
  }
}

/**
 * Validates an optional array, reporting a message per offending entry.
 *
 * The `check` callback returns the problem with an entry, or `undefined` when it
 * is acceptable. It receives the entry's own path so it can report deeper issues
 * itself.
 */
function checkArray(
  ctx: Context,
  value: unknown,
  path: string,
  check: (entry: unknown, entryPath: string) => string | undefined,
): void {
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value)) {
    add(ctx, path, "Must be an array");
    return;
  }
  for (const [index, entry] of (value as readonly unknown[]).entries()) {
    const entryPath = `${path}[${index}]`;
    const message = check(entry, entryPath);
    if (message !== undefined) {
      add(ctx, entryPath, message);
    }
  }
}

/** Validates an optional array of strings drawn from a fixed set. */
function checkEnumArray(
  ctx: Context,
  value: unknown,
  allowed: readonly string[],
  path: string,
): void {
  checkArray(ctx, value, path, (entry) =>
    typeof entry === "string" && allowed.includes(entry)
      ? undefined
      : `Must be one of ${allowed.map((item) => `"${item}"`).join(", ")}`,
  );
}

/** Validates an optional array of arbitrary non-empty strings. */
function checkStringArray(ctx: Context, value: unknown, path: string): void {
  checkArray(ctx, value, path, (entry) =>
    typeof entry === "string" && entry.length > 0
      ? undefined
      : "Must be a non-empty string",
  );
}

/** Validates an optional boolean. */
function checkBoolean(ctx: Context, value: unknown, path: string): void {
  if (value !== undefined && typeof value !== "boolean") {
    add(ctx, path, "Must be a boolean");
  }
}

/**
 * Explains why a `match` or `forEachScope` expression is unusable.
 *
 * An expression is either a resource pattern, or the canonical form of a scope
 * that is compared for exact equality - which is how non-resource scopes such
 * as `openid` and `launch/patient` are matched. A scope written in a
 * non-canonical form (a v1 suffix, say) would never compare equal, so it is
 * reported with the form to use instead.
 */
function matchExpressionIssue(value: string): string | undefined {
  if (parseScopePattern(value) !== undefined) {
    return undefined;
  }
  const parsed = parseScope(value);
  if (!parsed.ok) {
    return `"${value}" is not a scope pattern or a scope: ${parsed.message}`;
  }
  const canonical = formatScope(parsed.scope);
  if (canonical !== value) {
    return `"${value}" is not a scope pattern, and would be matched by exact equality against "${canonical}"; write it that way`;
  }
  return undefined;
}

/** Validates a `match`-style expression at `path`. */
function checkMatchExpression(
  ctx: Context,
  value: unknown,
  path: string,
): void {
  if (typeof value !== "string" || value.length === 0) {
    add(ctx, path, "Must be a non-empty scope pattern");
    return;
  }
  const issue = matchExpressionIssue(value);
  if (issue !== undefined) {
    add(ctx, path, issue);
  }
}

/** Validates one template string, reporting syntax and filter problems. */
function checkTemplate(ctx: Context, template: string, path: string): void {
  const parsed = parseTemplate(template);
  if (parsed.unterminated) {
    add(ctx, path, 'Unterminated "{{" in template');
  }

  for (const segment of parsed.segments) {
    if (segment.kind !== "interpolation") {
      continue;
    }
    if (segment.path.length === 0) {
      add(ctx, path, `Interpolation "{{${segment.raw}}}" has no path`);
    } else {
      for (const part of segment.path.split(".")) {
        if (!PATH_SEGMENT_PATTERN.test(part)) {
          add(ctx, path, `Invalid path segment "${part}" in "${segment.path}"`);
        }
      }
    }

    for (const filter of segment.filters) {
      if (!isTemplateFilterName(filter.name)) {
        add(ctx, path, `Unknown template filter "${filter.name}"`);
        continue;
      }
      if (
        filter.arg === undefined &&
        TEMPLATE_FILTERS_REQUIRING_ARGUMENT.includes(filter.name)
      ) {
        add(ctx, path, `Filter "${filter.name}" requires an argument`);
      }
      if (
        filter.arg !== undefined &&
        TEMPLATE_FILTERS_WITHOUT_ARGUMENT.includes(filter.name)
      ) {
        add(ctx, path, `Filter "${filter.name}" does not take an argument`);
      }
    }
  }
}

/** Validates a literal-or-template claim value, recursively. */
function checkTemplateValue(ctx: Context, value: unknown, path: string): void {
  if (typeof value === "string") {
    checkTemplate(ctx, value, path);
    return;
  }
  if (typeof value === "boolean" || value === null) {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      add(ctx, path, "Must be a finite number");
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const [index, entry] of (value as readonly unknown[]).entries()) {
      checkTemplateValue(ctx, entry, `${path}[${index}]`);
    }
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      checkTemplateValue(ctx, entry, `${path}.${key}`);
    }
    return;
  }
  add(ctx, path, "Must be a string, number, boolean, null, array or object");
}

/** Validates an `emit` block. */
function checkEmit(ctx: Context, value: unknown, path: string): void {
  if (!isRecord(value)) {
    add(ctx, path, "Must be an object of claim names to values");
    return;
  }
  for (const [name, entry] of Object.entries(value)) {
    if (name.length === 0) {
      add(ctx, path, "Claim names must not be empty");
      continue;
    }
    checkTemplateValue(ctx, entry, `${path}.${name}`);
  }
}

/** Validates a rule condition. */
function checkCondition(ctx: Context, value: unknown, path: string): void {
  if (!isRecord(value)) {
    add(ctx, path, "Must be an object");
    return;
  }
  checkKeys(ctx, value, CONDITION_KEYS, path);
  checkBoolean(ctx, value["always"], `${path}.always`);
  checkBoolean(ctx, value["hasUser"], `${path}.hasUser`);
  if (value["scope"] !== undefined) {
    checkMatchExpression(ctx, value["scope"], `${path}.scope`);
  }
  checkEnumArray(ctx, value["context"], LAUNCH_CONTEXT_KEYS, `${path}.context`);
  checkEnumArray(ctx, value["grantTypes"], GRANT_TYPES, `${path}.grantTypes`);
  checkEnumArray(
    ctx,
    value["clientTypes"],
    CLIENT_TYPES,
    `${path}.clientTypes`,
  );
  checkStringArray(ctx, value["userRole"], `${path}.userRole`);
}

/** Validates the fields every rule shares, including id uniqueness. */
function checkMetadata(
  ctx: Context,
  record: Record<string, unknown>,
  path: string,
): void {
  const id = record["id"];
  if (id !== undefined) {
    if (typeof id !== "string" || id.length === 0) {
      add(ctx, `${path}.id`, "Must be a non-empty string");
    } else {
      const first = ctx.ids.get(id);
      if (first === undefined) {
        ctx.ids.set(id, path);
      } else {
        add(
          ctx,
          `${path}.id`,
          `Duplicate rule id "${id}", already used by ${first}`,
        );
      }
    }
  }

  const description = record["description"];
  if (description !== undefined && typeof description !== "string") {
    add(ctx, `${path}.description`, "Must be a string");
  }
  checkBoolean(ctx, record["enabled"], `${path}.enabled`);
}

/** Validates a list of rules, delegating each entry to `check`. */
function checkRuleList(
  ctx: Context,
  value: unknown,
  path: string,
  required: boolean,
  check: (record: Record<string, unknown>, rulePath: string) => void,
): void {
  if (value === undefined) {
    if (required) {
      add(ctx, path, "Must be an array");
    }
    return;
  }
  checkArray(ctx, value, path, (entry, rulePath) => {
    if (!isRecord(entry)) {
      return "Must be an object";
    }
    checkMetadata(ctx, entry, rulePath);
    check(entry, rulePath);
    return;
  });
}

/** Validates the token lifetime defaults. */
function checkDefaults(ctx: Context, value: unknown): void {
  if (!isRecord(value)) {
    add(ctx, "defaults", "Must be an object");
    return;
  }
  checkKeys(ctx, value, DEFAULTS_KEYS, "defaults");
  for (const key of DEFAULTS_KEYS) {
    const ttl = value[key];
    if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl <= 0) {
      add(ctx, `defaults.${key}`, "Must be a positive integer of seconds");
    }
  }
}

/**
 * Validates an untrusted policy document.
 *
 * Everything is checked structurally before a document is accepted, because a
 * policy that fails at evaluation time fails in the middle of issuing a token -
 * far too late. Templates are checked for syntax and known filters only:
 * whether a path resolves depends on the authorization being evaluated, and an
 * unresolved path is a dropped claim rather than an error.
 *
 * @param input - Parsed JSON, of unknown shape.
 * @returns The document, narrowed to {@link PolicyDocument}, or the issues found.
 */
export function validatePolicy(input: unknown): PolicyValidation {
  if (!isRecord(input)) {
    return {
      ok: false,
      issues: [{ path: "", message: "Policy must be an object" }],
    };
  }

  const ctx: Context = { issues: [], ids: new Map<string, string>() };

  checkKeys(ctx, input, TOP_LEVEL_KEYS, "");

  if (input["version"] !== 1) {
    add(ctx, "version", "Must be the number 1");
  }

  checkRuleList(
    ctx,
    input["scopeGrants"],
    "scopeGrants",
    true,
    (rule, path) => {
      checkKeys(ctx, rule, GRANT_KEYS, path);
      checkMatchExpression(ctx, rule["match"], `${path}.match`);
      if (typeof rule["allow"] !== "boolean") {
        add(ctx, `${path}.allow`, "Must be a boolean");
      }
      if (rule["narrow"] !== undefined && typeof rule["narrow"] !== "boolean") {
        add(ctx, `${path}.narrow`, "Must be a boolean");
      }
      checkEnumArray(
        ctx,
        rule["requireContext"],
        REQUIRE_CONTEXT_KEYS,
        `${path}.requireContext`,
      );
      checkStringArray(ctx, rule["requireUserRole"], `${path}.requireUserRole`);
      checkEnumArray(
        ctx,
        rule["grantTypes"],
        GRANT_TYPES,
        `${path}.grantTypes`,
      );
      checkEnumArray(
        ctx,
        rule["clientTypes"],
        CLIENT_TYPES,
        `${path}.clientTypes`,
      );
    },
  );

  checkRuleList(ctx, input["claimRules"], "claimRules", true, (rule, path) => {
    checkKeys(ctx, rule, CLAIM_KEYS, path);
    if (rule["when"] === undefined) {
      add(ctx, `${path}.when`, "Must be a condition object");
    } else {
      checkCondition(ctx, rule["when"], `${path}.when`);
    }
    checkEmit(ctx, rule["emit"], `${path}.emit`);
  });

  checkRuleList(
    ctx,
    input["scopeMappings"],
    "scopeMappings",
    false,
    (rule, path) => {
      checkKeys(ctx, rule, MAPPING_KEYS, path);
      if (rule["when"] !== undefined) {
        checkCondition(ctx, rule["when"], `${path}.when`);
      }
      checkMatchExpression(ctx, rule["forEachScope"], `${path}.forEachScope`);
      const appendTo = rule["appendTo"];
      if (typeof appendTo !== "string" || appendTo.length === 0) {
        add(ctx, `${path}.appendTo`, "Must be a non-empty claim name");
      }
      const values = rule["values"];
      if (!Array.isArray(values) || values.length === 0) {
        add(ctx, `${path}.values`, "Must be a non-empty array of templates");
      } else {
        for (const [index, entry] of (values as readonly unknown[]).entries()) {
          if (typeof entry === "string") {
            checkTemplate(ctx, entry, `${path}.values[${index}]`);
          } else {
            add(ctx, `${path}.values[${index}]`, "Must be a string template");
          }
        }
      }
    },
  );

  checkRuleList(
    ctx,
    input["contextRules"],
    "contextRules",
    true,
    (rule, path) => {
      checkKeys(ctx, rule, CLAIM_KEYS, path);
      if (rule["when"] !== undefined) {
        checkCondition(ctx, rule["when"], `${path}.when`);
      }
      checkEmit(ctx, rule["emit"], `${path}.emit`);
    },
  );

  checkDefaults(ctx, input["defaults"]);

  if (ctx.issues.length > 0) {
    return { ok: false, issues: ctx.issues };
  }
  return { ok: true, policy: input as unknown as PolicyDocument };
}
