/**
 * The builder: the policy as a list of cards.
 *
 * This is the mode most operators should live in. Nothing here is typed except free
 * text - scope patterns are pickers, contexts and grant types are selects, and claim
 * values have an inserter listing the template variables - so the classes of mistake
 * the code view allows are not expressible.
 *
 * Two decisions run through it.
 *
 * Order is shown and editable, because order decides outcomes. In `scopeGrants` the
 * first matching rule wins; in `claimRules` a later rule overwrites an earlier one's
 * claim. Each card therefore carries its position and a pair of move buttons, and the
 * lists say what their ordering means.
 *
 * A rule the builder cannot represent is rendered read-only rather than approximated. A
 * grant rule whose `match` carries search parameters, or a claim rule whose condition
 * combines fields the cards do not offer, is shown as its JSON with a note to edit it in
 * the code view - so the builder never silently drops or rewrites part of a policy it
 * did not fully understand.
 *
 * Author: John Grimes
 */

import { useState } from "react";

import { ClaimRuleFields } from "./claimRuleFields.js";
import { GrantRuleFields } from "./grantRuleFields.js";
import { MappingRuleFields } from "./mappingRuleFields.js";
import { DEFAULT_PATTERN, formatPattern } from "./patterns.js";
import { RuleCard } from "./ruleCard.js";
import {
  appendRule,
  generateRuleId,
  isRuleEnabled,
  replaceRule,
  rulesIn,
  usedRuleIds,
} from "./rules.js";
import { summariseRule } from "./summaries.js";
import { TextField } from "../components/fields.js";
import { EmptyState, Panel } from "../components/layout.js";
import { parsePositiveInteger } from "../forms/lists.js";

import type { AnyRule, RuleList } from "./rules.js";
import type {
  ClaimRule,
  ContextRule,
  PolicyDocument,
  ScopeGrantRule,
  ScopeMappingRule,
} from "@signet/core";

interface RuleBuilderProps {
  readonly document: PolicyDocument;
  readonly onChange: (document: PolicyDocument) => void;
  readonly disabled: boolean;
}

/** What each list is, and what its ordering means. */
const LIST_DESCRIPTIONS: Readonly<
  Record<RuleList, { readonly title: string; readonly description: string }>
> = {
  scopeGrants: {
    title: "Scope grants",
    description:
      "Which requested scopes are granted. The first rule whose pattern matches decides, so a deny placed above an allow wins. A scope matching no rule is denied.",
  },
  claimRules: {
    title: "Claims",
    description:
      "What goes into the signed access token. Every matching rule contributes, and a later rule overwrites an earlier one's claim of the same name.",
  },
  scopeMappings: {
    title: "Scope mappings",
    description:
      "Translates each granted scope into a resource server's own vocabulary, accumulating into an array claim. This is what turns SMART scopes into a vendor's authorities.",
  },
  contextRules: {
    title: "Response parameters",
    description:
      "What accompanies the token in the response body rather than inside it - the launch context an app reads to know which patient it was opened for.",
  },
};

/** The whole builder. */
export function RuleBuilder({
  document,
  onChange,
  disabled,
}: Readonly<RuleBuilderProps>) {
  return (
    <>
      <RuleSection
        list="scopeGrants"
        document={document}
        onChange={onChange}
        disabled={disabled}
        newRule={() => ({
          match: formatPattern(DEFAULT_PATTERN),
          allow: true,
          narrow: true,
        })}
      />
      <RuleSection
        list="claimRules"
        document={document}
        onChange={onChange}
        disabled={disabled}
        newRule={() => ({ when: { always: true }, emit: {} })}
      />
      <RuleSection
        list="scopeMappings"
        document={document}
        onChange={onChange}
        disabled={disabled}
        newRule={() => ({
          forEachScope: "*/*.r",
          appendTo: "authorities",
          values: [""],
        })}
      />
      <RuleSection
        list="contextRules"
        document={document}
        onChange={onChange}
        disabled={disabled}
        newRule={() => ({ emit: {} })}
      />
      <DefaultsSection
        document={document}
        onChange={onChange}
        disabled={disabled}
      />
    </>
  );
}

interface RuleSectionProps {
  readonly list: RuleList;
  readonly document: PolicyDocument;
  readonly onChange: (document: PolicyDocument) => void;
  readonly disabled: boolean;
  /** Builds the rule the "Add" button appends. */
  readonly newRule: () => AnyRule;
}

/** One list of rules, collapsed to summaries, with its ordering explained. */
function RuleSection({
  list,
  document,
  onChange,
  disabled,
  newRule,
}: Readonly<RuleSectionProps>) {
  const rules = rulesIn(document, list);
  const meta = LIST_DESCRIPTIONS[list];

  // Which rules are open for editing. Collapsed by default so the list reads as a
  // list; a rule the operator has just added opens itself, because the next thing
  // they will do is fill it in.
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  /** Opens or closes one rule. */
  const toggle = (key: string) => {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  return (
    <Panel
      title={meta.title}
      description={meta.description}
      actions={
        disabled ? undefined : (
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => {
              // The identifier is chosen here rather than left to appendRule, so
              // the new card can be expanded for editing.
              const id = generateRuleId(list, usedRuleIds(document));
              onChange(appendRule(document, list, { ...newRule(), id }));
              setExpanded((current) => new Set(current).add(id));
            }}
          >
            Add rule
          </button>
        )
      }
    >
      {rules.length === 0 ? (
        <EmptyState
          title="No rules"
          description={
            list === "scopeGrants"
              ? "With no grant rules, every requested scope is denied and no token can be issued."
              : "Nothing is emitted from this list."
          }
        />
      ) : (
        <ol className="flex flex-col gap-3">
          {rules.map((rule, index) => (
            <li key={rule.id ?? String(index)}>
              <RuleCard
                list={list}
                document={document}
                rule={rule}
                position={index + 1}
                total={rules.length}
                summary={summariseRule(list, rule)}
                enabled={isRuleEnabled(rule)}
                disabled={disabled}
                expanded={expanded.has(rule.id ?? String(index))}
                onToggle={() => {
                  toggle(rule.id ?? String(index));
                }}
                onChange={onChange}
              >
                {renderFields(list, rule, disabled, (next) => {
                  onChange(replaceRule(document, list, rule.id ?? "", next));
                })}
              </RuleCard>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

/** Chooses the field set for a list. */
function renderFields(
  list: RuleList,
  rule: AnyRule,
  disabled: boolean,
  onChange: (rule: AnyRule) => void,
) {
  switch (list) {
    case "scopeGrants": {
      return (
        <GrantRuleFields
          rule={rule as ScopeGrantRule}
          disabled={disabled}
          onChange={onChange}
        />
      );
    }
    case "claimRules": {
      return (
        <ClaimRuleFields
          rule={rule as ClaimRule}
          disabled={disabled}
          withCondition
          onChange={onChange}
        />
      );
    }
    case "contextRules": {
      return (
        <ClaimRuleFields
          rule={rule as ContextRule}
          disabled={disabled}
          withCondition={false}
          onChange={onChange}
        />
      );
    }
    case "scopeMappings": {
      return (
        <MappingRuleFields
          rule={rule as ScopeMappingRule}
          disabled={disabled}
          onChange={onChange}
        />
      );
    }
  }
}

/** The token lifetimes, which are not rules but live in the same document. */
function DefaultsSection({
  document,
  onChange,
  disabled,
}: Readonly<{
  readonly document: PolicyDocument;
  readonly onChange: (document: PolicyDocument) => void;
  readonly disabled: boolean;
}>) {
  const [accessTtl, setAccessTtl] = useState(
    String(document.defaults.accessTokenTtl),
  );
  const [refreshTtl, setRefreshTtl] = useState(
    String(document.defaults.refreshTokenTtl),
  );

  /** Writes a lifetime back, ignoring a value that is not yet a number. */
  const commit = (
    field: "accessTokenTtl" | "refreshTokenTtl",
    text: string,
  ) => {
    const seconds = parsePositiveInteger(text);
    if (seconds === undefined) {
      return;
    }
    onChange({
      ...document,
      defaults: { ...document.defaults, [field]: seconds },
    });
  };

  return (
    <Panel
      title="Lifetimes"
      description="What this policy issues tokens for. The endpoint's own settings are the default; a policy may shorten or lengthen them."
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          label="Access token lifetime (seconds)"
          value={accessTtl}
          disabled={disabled}
          onChange={(value) => {
            setAccessTtl(value);
            commit("accessTokenTtl", value);
          }}
        />
        <TextField
          label="Refresh token lifetime (seconds)"
          value={refreshTtl}
          disabled={disabled}
          onChange={(value) => {
            setRefreshTtl(value);
            commit("refreshTokenTtl", value);
          }}
        />
      </div>
    </Panel>
  );
}
