/**
 * A scope mapping rule's fields.
 *
 * This is the rule type Signet exists for: it runs once per granted scope and appends
 * to an array claim, which is how SMART scopes become a resource server's own
 * vocabulary. The Pathling preset is the worked example — `patient/Observation.rs`
 * becomes `["pathling:read:Observation", "pathling:search"]`.
 *
 * Two things the fields say out loud, because both are easy to get wrong. The pattern
 * here matches differently from a grant rule's: a mapping fires when the scope shares
 * any* permission with the pattern, so a read pattern over every context and type
 * fires for `patient/Observation.rs`. And
 * `scope.resourceTypeSuffix` is the variable that makes one template serve both a typed
 * scope and a wildcard, which is not something an operator would guess.
 */

import { PatternField } from "./patternField.js";
import { ListField, TextField } from "../components/fields.js";
import { formatList, parseList } from "../forms/lists.js";

import type { ScopeMappingRule } from "@signet/core";

interface MappingRuleFieldsProps {
  readonly rule: ScopeMappingRule;
  readonly disabled: boolean;
  readonly onChange: (rule: ScopeMappingRule) => void;
}

/** The fields of one scope mapping rule. */
export function MappingRuleFields({
  rule,
  disabled,
  onChange,
}: Readonly<MappingRuleFieldsProps>) {
  return (
    <>
      <PatternField
        label="For each granted scope matching"
        value={rule.forEachScope}
        disabled={disabled}
        hint="Fires when the scope shares at least one permission with this pattern — unlike a grant rule, where the scope's permissions must be a subset. So */*.r fires for patient/Observation.rs."
        onChange={(forEachScope) => {
          onChange({ ...rule, forEachScope });
        }}
      />

      <TextField
        label="Append to claim"
        value={rule.appendTo}
        disabled={disabled}
        hint="The array claim to accumulate into. Created if the token does not have it yet. Pathling reads `authorities`."
        onChange={(appendTo) => {
          onChange({ ...rule, appendTo });
        }}
      />

      <ListField
        label="Values"
        value={formatList(rule.values)}
        disabled={disabled}
        rows={3}
        hint="One template per line, evaluated with `scope` bound to the matching scope. Use {{ scope.resourceTypeSuffix }} to get `:Observation` for a typed scope and nothing for a wildcard, so one template covers both."
        onChange={(text) => {
          onChange({ ...rule, values: parseList(text) });
        }}
      />
    </>
  );
}
