/**
 * A claim or context rule's fields: a condition, and what to emit.
 *
 * The emitted claims are key/value rows with a variable inserter beside each value,
 * which is the single most useful thing in the builder - nobody should have to remember
 * whether it is `context.patient` or `launch.patient`, and the answer is not guessable.
 *
 * Values are edited as text and stored as text. A policy may emit a number, a boolean or
 * an array, and the code view is where those are written: a key/value row that tried to
 * offer a type picker would be a worse editor for the common case, which is a template
 * string. A value that is already a non-string is shown read-only, with a note, rather
 * than being stringified into something different.
 *
 * The value input and the inserter beside it are the two smallest controls in the
 * console - `input-sm` at 12px, and a `select-sm` capped at 128px - which makes them the
 * two most in need of the responsive sizing every other control gets from `fields.tsx`.
 * They are raw elements rather than a `TextField` because the pair shares one row and a
 * caret position, so the sizing is repeated here rather than inherited.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { insertVariable, TEMPLATE_VARIABLES } from "./variables.js";
import { SelectField, TextField } from "../components/fields.js";

import type { ClaimRule, ContextRule, RuleCondition } from "@signet/core";

/** A rule that emits claims. Both kinds have `emit`; only one has a condition. */
type EmittingRule = ClaimRule | ContextRule;

interface ClaimRuleFieldsProps {
  readonly rule: EmittingRule;
  readonly disabled: boolean;
  /** Context rules may omit their condition entirely, and usually do. */
  readonly withCondition: boolean;
  readonly onChange: (rule: EmittingRule) => void;
}

/** The condition shapes the builder offers, in the order they are usually wanted. */
const CONDITION_KINDS = [
  { value: "always", label: "Always" },
  { value: "hasUser", label: "When there is a signed-in user" },
  { value: "noUser", label: "When there is no user (a backend service)" },
  { value: "scope", label: "When a granted scope matches a pattern" },
  { value: "context", label: "When the launch context has a value" },
] as const;

/** Which of the offered shapes a condition is, or undefined for one that is none. */
function conditionKind(
  condition: RuleCondition | undefined,
): (typeof CONDITION_KINDS)[number]["value"] | undefined {
  if (condition === undefined || condition.always === true) {
    return "always";
  }
  if (condition.hasUser === true) {
    return "hasUser";
  }
  if (condition.hasUser === false) {
    return "noUser";
  }
  if (condition.scope !== undefined) {
    return "scope";
  }
  if (condition.context !== undefined) {
    return "context";
  }
  return undefined;
}

/** The fields of one claim or context rule. */
export function ClaimRuleFields({
  rule,
  disabled,
  withCondition,
  onChange,
}: Readonly<ClaimRuleFieldsProps>) {
  const condition = "when" in rule ? rule.when : undefined;
  const kind = conditionKind(condition);

  return (
    <>
      {withCondition ? (
        kind === undefined ? (
          <p className="text-warning text-xs max-sm:text-base">
            This rule&apos;s condition combines fields the builder does not
            offer. Edit it in the code view; nothing here will change it.
          </p>
        ) : (
          <>
            <SelectField
              label="When"
              value={kind}
              disabled={disabled}
              options={[...CONDITION_KINDS]}
              onChange={(next) => {
                onChange({
                  ...rule,
                  when: conditionFor(next as typeof kind, condition),
                });
              }}
            />
            {kind === "scope" ? (
              <TextField
                label="Scope pattern"
                value={condition?.scope ?? ""}
                disabled={disabled}
                hint="At least one granted scope must fall within this pattern, e.g. patient/*.rs."
                onChange={(scope) => {
                  onChange({ ...rule, when: { scope } });
                }}
              />
            ) : null}
            {kind === "context" ? (
              <TextField
                label="Launch context keys"
                value={(condition?.context ?? []).join(" ")}
                disabled={disabled}
                hint="Space-separated. All of them must be present and non-empty, e.g. patient encounter."
                onChange={(text) => {
                  const keys = text
                    .split(/\s+/)
                    .filter((key) => key.length > 0) as NonNullable<
                    RuleCondition["context"]
                  >;
                  onChange({
                    ...rule,
                    when: { context: keys },
                  });
                }}
              />
            ) : null}
          </>
        )
      ) : null}

      <EmitRows
        emit={rule.emit}
        disabled={disabled}
        onChange={(emit) => {
          onChange({ ...rule, emit } as EmittingRule);
        }}
      />
    </>
  );
}

/** Builds the condition for a chosen shape, keeping what still applies. */
function conditionFor(
  kind: (typeof CONDITION_KINDS)[number]["value"],
  previous: RuleCondition | undefined,
): RuleCondition {
  switch (kind) {
    case "always": {
      return { always: true };
    }
    case "hasUser": {
      return { hasUser: true };
    }
    case "noUser": {
      return { hasUser: false };
    }
    case "scope": {
      return { scope: previous?.scope ?? "patient/*.rs" };
    }
    case "context": {
      return { context: previous?.context ?? ["patient"] };
    }
  }
}

interface EmitRowsProps {
  readonly emit: Readonly<Record<string, unknown>>;
  readonly disabled: boolean;
  readonly onChange: (emit: Readonly<Record<string, unknown>>) => void;
}

/** The claims a rule emits, as editable rows. */
function EmitRows({ emit, disabled, onChange }: Readonly<EmitRowsProps>) {
  const [newName, setNewName] = useState("");
  const entries = Object.entries(emit);

  return (
    <div>
      <span className="label-text text-sm max-sm:text-base">Emits</span>

      {entries.length === 0 ? (
        <p className="text-base-content/60 mt-1 text-xs max-sm:text-base">
          Nothing yet. A rule that emits nothing has no effect.
        </p>
      ) : (
        <ul className="mt-2 flex flex-col gap-2">
          {entries.map(([name, value]) => (
            <li key={name} className="flex flex-wrap items-end gap-2">
              <code className="bg-base-200 rounded-field px-2 py-1 font-mono text-xs">
                {name}
              </code>
              <div className="min-w-48 flex-1">
                {typeof value === "string" ? (
                  <ValueField
                    name={name}
                    value={value}
                    disabled={disabled}
                    onChange={(next) => {
                      onChange({ ...emit, [name]: next });
                    }}
                  />
                ) : (
                  <p className="text-base-content/70 font-mono text-xs break-all">
                    {JSON.stringify(value)}{" "}
                    <span className="text-warning">
                      - not a string; edit in the code view
                    </span>
                  </p>
                )}
              </div>
              {disabled ? null : (
                <button
                  type="button"
                  className="btn btn-ghost btn-xs text-error"
                  onClick={() => {
                    const { [name]: _dropped, ...rest } = emit;
                    onChange(rest);
                  }}
                >
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {disabled ? null : (
        <div className="mt-2 flex items-end gap-2">
          <div className="flex-1">
            <TextField
              label="Add a claim"
              value={newName}
              onChange={setNewName}
              hint="The claim name as it appears in the token."
            />
          </div>
          <button
            type="button"
            className="btn btn-outline btn-sm"
            disabled={newName.trim().length === 0}
            onClick={() => {
              onChange({ ...emit, [newName.trim()]: "" });
              setNewName("");
            }}
          >
            Add
          </button>
        </div>
      )}
    </div>
  );
}

interface ValueFieldProps {
  readonly name: string;
  readonly value: string;
  readonly disabled: boolean;
  readonly onChange: (value: string) => void;
}

/** One claim's value, with the variable inserter beside it. */
function ValueField({
  name,
  value,
  disabled,
  onChange,
}: Readonly<ValueFieldProps>) {
  const [caret, setCaret] = useState(value.length);

  return (
    <div className="flex items-end gap-1">
      <label className="flex-1">
        <span className="sr-only">{`Value for ${name}`}</span>
        <input
          type="text"
          className="input input-bordered input-sm w-full font-mono text-xs max-sm:min-h-11 max-sm:text-base"
          value={value}
          disabled={disabled}
          aria-label={`Value for ${name}`}
          onChange={(event) => {
            setCaret(event.currentTarget.selectionStart ?? value.length);
            onChange(event.currentTarget.value);
          }}
          onSelect={(event) => {
            setCaret(event.currentTarget.selectionStart ?? value.length);
          }}
        />
      </label>
      {disabled ? null : (
        <select
          className="select select-bordered select-sm max-w-32 max-sm:min-h-11 max-sm:text-base"
          aria-label={`Insert a variable into ${name}`}
          value=""
          onChange={(event) => {
            const path = event.currentTarget.value;
            if (path.length > 0) {
              onChange(insertVariable(value, path, caret));
            }
          }}
        >
          <option value="">Insert…</option>
          {TEMPLATE_VARIABLES.map((variable) => (
            <option
              key={variable.path}
              value={variable.path}
              title={variable.description}
            >
              {variable.path}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}
