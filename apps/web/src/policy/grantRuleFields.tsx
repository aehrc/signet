/**
 * A grant rule's fields.
 *
 * The two that matter most are `allow` and `narrow`, and neither is obvious from its
 * name, so both are stated. `allow: false` is a deny that no later rule can override,
 * because the first match wins. `narrow` is what makes a read-only policy answer an app
 * asking for `patient/*.cruds` with `patient/*.rs` rather than with nothing - the spec
 * permits granting less than was requested, and real apps routinely ask for everything.
 *
 * Author: John Grimes
 */

import { PatternField } from "./patternField.js";
import { withFields } from "./rules.js";
import { CheckboxField, ListField, SelectField } from "../components/fields.js";
import { formatList, parseList } from "../forms/lists.js";

import type { ScopeGrantRule } from "@signet/core";

interface GrantRuleFieldsProps {
  readonly rule: ScopeGrantRule;
  readonly disabled: boolean;
  readonly onChange: (rule: ScopeGrantRule) => void;
}

/** Every launch context key a grant rule may require. */
const CONTEXT_REQUIREMENTS: readonly ("patient" | "encounter")[] = [
  "patient",
  "encounter",
];

/** The fields of one grant rule. */
export function GrantRuleFields({
  rule,
  disabled,
  onChange,
}: Readonly<GrantRuleFieldsProps>) {
  /** Applies a patch, dropping keys whose value became nothing. */
  const patch = (changes: Readonly<Record<string, unknown>>) => {
    onChange(withFields(rule, changes) as ScopeGrantRule);
  };

  return (
    <>
      <PatternField
        label="Matches"
        value={rule.match}
        disabled={disabled}
        hint="A requested scope matches when its permissions are a subset of these. patient/*.rs matches patient/Observation.r but not patient/Observation.cud."
        onChange={(match) => {
          patch({ match });
        }}
      />

      <SelectField
        label="Decision"
        value={rule.allow ? "allow" : "deny"}
        disabled={disabled}
        options={[
          { value: "allow", label: "Allow - grant this scope" },
          { value: "deny", label: "Deny - refuse it, and stop looking" },
        ]}
        hint="The first matching rule decides, so a deny placed above an allow wins and cannot be narrowed around."
        onChange={(decision) => {
          patch({ allow: decision === "allow" });
        }}
      />

      <CheckboxField
        label="Narrow instead of refusing"
        checked={rule.narrow === true}
        disabled={disabled}
        hint="When an app asks for more permissions than this rule permits, grant the overlap rather than nothing. Without it, a read-only policy answers a request for patient/*.cruds with no data access at all - which fails at the app's first API call rather than degrading to read."
        onChange={(narrow) => {
          patch({ narrow });
        }}
      />

      <div>
        <span className="label-text text-sm max-sm:text-base">
          Requires launch context
        </span>
        <div className="mt-1 flex flex-wrap gap-3">
          {CONTEXT_REQUIREMENTS.map((key) => (
            <label
              key={key}
              className="flex cursor-pointer items-center gap-1 text-sm max-sm:min-h-11 max-sm:text-base"
            >
              <input
                type="checkbox"
                className="checkbox checkbox-xs"
                disabled={disabled}
                checked={(rule.requireContext ?? []).includes(key)}
                onChange={(event) => {
                  const current = rule.requireContext ?? [];
                  const next = event.currentTarget.checked
                    ? [...current, key]
                    : current.filter((existing) => existing !== key);
                  patch({
                    requireContext: next.length === 0 ? undefined : next,
                  });
                }}
              />
              <code className="font-mono">{key}</code>
            </label>
          ))}
        </div>
        <p className="text-base-content/60 mt-1 text-xs max-sm:text-base">
          Granting a patient-context scope with no patient resolved would hand
          the app a token whose meaning depends on what the FHIR server infers.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <ListField
          label="Only for these grant types"
          value={formatList(rule.grantTypes)}
          disabled={disabled}
          rows={2}
          hint="One per line: authorization_code, client_credentials, refresh_token. Leave empty for all of them."
          onChange={(text) => {
            const values = parseList(text);
            patch({
              grantTypes: values.length === 0 ? undefined : values,
            });
          }}
        />
        <ListField
          label="Only for these client types"
          value={formatList(rule.clientTypes)}
          disabled={disabled}
          rows={2}
          hint="One per line: public, confidential-symmetric, confidential-asymmetric."
          onChange={(text) => {
            const values = parseList(text);
            patch({
              clientTypes: values.length === 0 ? undefined : values,
            });
          }}
        />
      </div>

      <ListField
        label="Only for users holding one of these roles"
        value={formatList(rule.requireUserRole)}
        disabled={disabled}
        rows={2}
        hint="One per line. Leave empty to place no role requirement."
        onChange={(text) => {
          const values = parseList(text);
          patch({
            requireUserRole: values.length === 0 ? undefined : values,
          });
        }}
      />
    </>
  );
}
