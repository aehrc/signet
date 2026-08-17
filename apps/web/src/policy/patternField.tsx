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
 * The five boxes stay five boxes on a phone. They wrap onto as many rows as they need
 * and each row is a 44px tap target, because the alternative - hiding them behind the
 * text field they exist to replace - would take the difference between `.rs` and
 * `.cruds` away from exactly the reader least able to check it.
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
      <legend className="px-1 text-sm max-sm:text-base font-medium">
        {label}
      </legend>
      {hint === undefined ? null : (
        <p className="text-base-content/60 mb-2 text-xs max-sm:text-base">
          {hint}
        </p>
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

      <fieldset className="fieldset mt-2 min-w-0">
        <legend className="fieldset-legend text-sm max-sm:text-base">
          Permissions
        </legend>
        <div className="flex flex-wrap gap-3">
          {PERMISSION_ORDER.map((permission) => (
            <label
              key={permission}
              className="flex cursor-pointer items-center gap-1 text-sm max-sm:min-h-11 max-sm:text-base"
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
      </fieldset>

      {/* The pattern as it will be stored. `break-all` because it is one word
          with nothing in it to break at, and at 360px a long resource type puts
          it past the edge of the card. */}
      <p className="text-base-content/60 mt-2 font-mono text-xs break-all">
        {value}
      </p>

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
