/**
 * The frame around one rule.
 *
 * Carries the four things every rule has regardless of kind: its position in the list,
 * a way to move it, a switch that disables it without deleting it, and a description.
 *
 * The move buttons are buttons rather than a drag handle. Dragging is nicer with a mouse
 * and unusable without one, and reordering a policy rule is a decision with
 * consequences - a keyboard-reachable pair of buttons is both accessible and harder to
 * do by accident.
 *
 * Author: John Grimes
 */

import { moveRule, removeRule, replaceRule, setRuleEnabled } from "./rules.js";
import { CheckboxField, TextField } from "../components/fields.js";

import type { AnyRule, RuleList } from "./rules.js";
import type { PolicyDocument } from "@signet/core";
import type { ReactNode } from "react";

interface RuleCardProps {
  readonly list: RuleList;
  readonly document: PolicyDocument;
  readonly rule: AnyRule;
  /** One-based position, shown because order decides outcomes. */
  readonly position: number;
  readonly total: number;
  readonly enabled: boolean;
  readonly disabled: boolean;
  readonly onChange: (document: PolicyDocument) => void;
  readonly children: ReactNode;
}

/** One rule, with its controls. */
export function RuleCard({
  list,
  document,
  rule,
  position,
  total,
  enabled,
  disabled,
  onChange,
  children,
}: Readonly<RuleCardProps>) {
  const id = rule.id ?? "";

  return (
    <div
      className={`border-base-300 rounded-box border p-3 ${
        enabled ? "" : "bg-base-200 opacity-70"
      }`}
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className="badge badge-neutral badge-sm font-mono">
          {position}
        </span>
        <code className="text-base-content/60 flex-1 font-mono text-xs">
          {id}
        </code>

        {disabled ? null : (
          <>
            <div className="join">
              <button
                type="button"
                className="btn btn-ghost btn-xs join-item"
                aria-label="Move earlier"
                disabled={position === 1}
                onClick={() => {
                  onChange(moveRule(document, list, id, -1));
                }}
              >
                ↑
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-xs join-item"
                aria-label="Move later"
                disabled={position === total}
                onClick={() => {
                  onChange(moveRule(document, list, id, 1));
                }}
              >
                ↓
              </button>
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-xs text-error"
              onClick={() => {
                onChange(removeRule(document, list, id));
              }}
            >
              Delete
            </button>
          </>
        )}
      </div>

      <div className="flex flex-col gap-3">
        {children}

        <TextField
          label="Description"
          value={rule.description ?? ""}
          disabled={disabled}
          hint="Why this rule exists. The code view has no comments, so this is where the reasoning lives."
          onChange={(value) => {
            const next =
              value.trim().length === 0
                ? withoutDescription(rule)
                : { ...rule, description: value };
            onChange(replaceRule(document, list, id, next));
          }}
        />

        <CheckboxField
          label="Enabled"
          checked={enabled}
          disabled={disabled}
          hint="A disabled rule stays in the policy and is skipped. Useful for turning something off to see what changes, without losing it."
          onChange={(checked) => {
            onChange(setRuleEnabled(document, list, id, checked));
          }}
        />
      </div>
    </div>
  );
}

/**
 * Drops an emptied description rather than storing `""`.
 *
 * An empty string in the code view is something a reader has to decide to ignore.
 */
function withoutDescription(rule: AnyRule): AnyRule {
  const { description: _dropped, ...rest } = rule;
  return rest;
}
