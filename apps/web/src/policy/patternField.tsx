/**
 * A scope pattern, as three controls rather than a string.
 *
 * The permission checkboxes are the reason this exists: a pattern's suffix must read in
 * `cruds` order, and the difference between `.rs` and `.cruds` is the difference between
 * a read-only policy and one that permits deletion. Five labelled boxes say that; a text
 * field says `patient/*.rs` and hopes.
 *
 * A pattern the pickers cannot represent - one carrying search parameters, or a
 * non-resource scope like `openid` - falls back to a plain text field, so the builder
 * never rewrites a value it did not fully parse.
 *
 * Author: John Grimes
 */

import { PERMISSION_ORDER } from "@signet/core";

import {
  COMMON_RESOURCE_TYPES,
  formatPattern,
  patternDraft,
  PERMISSION_LABELS,
  withPermission,
} from "./patterns.js";
import { SelectField, TextField } from "../components/fields.js";

import type { ReactNode } from "react";

interface PatternFieldProps {
  readonly label: string;
  readonly hint?: ReactNode;
  readonly value: string;
  readonly onChange: (pattern: string) => void;
  readonly disabled: boolean;
}

/** The pattern editor. */
export function PatternField({
  label,
  hint,
  value,
  onChange,
  disabled,
}: Readonly<PatternFieldProps>) {
  const draft = patternDraft(value);

  if (draft === undefined) {
    return (
      <TextField
        label={label}
        value={value}
        onChange={onChange}
        disabled={disabled}
        hint={
          <>
            Matched by exact equality rather than as a pattern - `openid`,
            `launch/patient` and `offline_access` are named, not matched. Edit
            it as text.
          </>
        }
      />
    );
  }

  return (
    <fieldset className="border-base-300 rounded-box border p-3">
      <legend className="px-1 text-sm font-medium">{label}</legend>
      {hint === undefined ? null : (
        <p className="text-base-content/60 mb-2 text-xs">{hint}</p>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <SelectField
          label="Context"
          value={draft.context}
          disabled={disabled}
          options={[
            { value: "patient", label: "patient - a patient's record" },
            { value: "user", label: "user - everything the user may see" },
            { value: "system", label: "system - a backend service" },
            { value: "*", label: "* - any context" },
          ]}
          onChange={(context) => {
            onChange(
              formatPattern({
                ...draft,
                context: context as typeof draft.context,
              }),
            );
          }}
        />
        <div>
          <TextField
            label="Resource type"
            value={draft.resourceType}
            disabled={disabled}
            hint="A FHIR resource type, or * for every type."
            onChange={(resourceType) => {
              onChange(formatPattern({ ...draft, resourceType }));
            }}
          />
        </div>
      </div>

      <div className="mt-2">
        <span className="label-text text-sm">Permissions</span>
        <div className="mt-1 flex flex-wrap gap-3">
          {PERMISSION_ORDER.map((permission) => (
            <label
              key={permission}
              className="flex cursor-pointer items-center gap-1 text-sm"
            >
              <input
                type="checkbox"
                className="checkbox checkbox-xs"
                disabled={disabled}
                checked={draft.permissions.includes(permission)}
                onChange={(event) => {
                  onChange(
                    formatPattern(
                      withPermission(
                        draft,
                        permission,
                        event.currentTarget.checked,
                      ),
                    ),
                  );
                }}
              />
              <span>
                <code className="font-mono">{permission}</code>{" "}
                {PERMISSION_LABELS[permission]}
              </span>
            </label>
          ))}
        </div>
      </div>

      <p className="text-base-content/60 mt-2 font-mono text-xs">{value}</p>

      {/* A datalist rather than a select: FHIR has around 150 resource types, and
          the field accepts anything the grammar does. */}
      <datalist id="signet-resource-types">
        {COMMON_RESOURCE_TYPES.map((type) => (
          <option key={type} value={type} />
        ))}
      </datalist>
    </fieldset>
  );
}
