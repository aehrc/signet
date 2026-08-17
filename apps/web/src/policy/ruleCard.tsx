/**
 * The frame around one rule.
 *
 * Collapsed by default: a policy of any size is unreadable as a stack of open
 * forms, so until it is expanded a rule is its position and a one-line summary of
 * what it does. That is also what makes reordering usable - a list's order fits on
 * one screen, rather than one card per screenful.
 *
 * Carries the four things every rule has regardless of kind: its position in the
 * list, a way to move it, a switch that disables it without deleting it, and a
 * description.
 *
 * The move buttons are buttons rather than a drag handle. Dragging is nicer with a mouse
 * and unusable without one, and reordering a policy rule is a decision with
 * consequences - a keyboard-reachable pair of buttons is both accessible and harder to
 * do by accident. They are icon-only, which is what makes them a mobile problem: the
 * panel around them gives every button 44px of height below `sm`, but an icon with
 * `btn-xs` padding is 32px wide, so the width is set here.
 *
 * The summary is truncated to one line on a desktop, where a card is 700px wide and a
 * second line would loosen a list meant to be scanned. At 360px that same truncation
 * cuts "Allow user/*.cruds · narrows · role pathling-admin" off after the pattern, so
 * below `sm` it wraps instead: the collapsed list is the only place the order of a
 * policy is visible, and a list of rules that all read "Allow user/*.cr…" is not one.
 *
 * Author: John Grimes
 */

import {
  ArrowDownIcon,
  ArrowUpIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  TrashIcon,
} from "@primer/octicons-react";

import { moveRule, removeRule, replaceRule, setRuleEnabled } from "./rules.js";
import { CheckboxField, TextField } from "../components/fields.js";

import type { AnyRule, RuleList } from "./rules.js";
import type { PolicyDocument } from "@signet/core";
import type { ReactNode } from "react";

/**
 * One line on a desktop, as many as it needs on a phone.
 *
 * `truncate` is three declarations, so undoing it below `sm` takes three classes:
 * the ellipsis, the clipping and the nowrap all have to go, or the text is still
 * one line.
 */
const SUMMARY_LINE =
  "block truncate max-sm:overflow-visible max-sm:text-clip max-sm:break-words max-sm:whitespace-normal";

/** The icon-only controls in a card's header, at a size a thumb can hit. */
const ICON_BUTTON = "btn btn-ghost btn-xs max-sm:min-h-11 max-sm:min-w-11";

interface RuleCardProps {
  readonly list: RuleList;
  readonly document: PolicyDocument;
  readonly rule: AnyRule;
  /** One-based position, shown because order decides outcomes. */
  readonly position: number;
  readonly total: number;
  /** What the rule does, in one line. All the card shows until expanded. */
  readonly summary: string;
  readonly enabled: boolean;
  readonly disabled: boolean;
  readonly expanded: boolean;
  readonly onToggle: () => void;
  readonly onChange: (document: PolicyDocument) => void;
  readonly children: ReactNode;
}

/** One rule, collapsed to its summary until expanded for editing. */
export function RuleCard({
  list,
  document,
  rule,
  position,
  total,
  summary,
  enabled,
  disabled,
  expanded,
  onToggle,
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
      <div className="flex flex-wrap items-center gap-2 max-sm:flex-col max-sm:items-stretch">
        <button
          type="button"
          className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left max-sm:min-h-11 max-sm:flex-col max-sm:items-stretch"
          aria-expanded={expanded}
          title={id}
          onClick={onToggle}
        >
          {/* On a phone the position, the off marker and the chevron form their own
              row above the summary; on a desktop `sm:contents` dissolves the wrapper
              and the `sm:order-*` classes restore the inline order of
              badge · summary · off · chevron. */}
          <span className="flex items-center gap-2 sm:contents">
            <span className="badge badge-neutral badge-sm shrink-0 font-mono">
              {position}
            </span>
            {enabled ? null : (
              <span className="badge badge-sm sm:order-2">off</span>
            )}
            <span
              aria-hidden="true"
              className="text-base-content/60 ml-auto sm:order-3 sm:ml-0"
            >
              {expanded ? (
                <ChevronUpIcon size={12} />
              ) : (
                <ChevronDownIcon size={12} />
              )}
            </span>
          </span>
          <span className="min-w-0 flex-1 sm:order-1">
            {/* `data-prose` on both, because both are sentences addressed to the
                reader and neither can be a `p`: a button's content model admits
                phrasing content only. It is what puts them inside the 16px floor
                the responsive suite measures. */}
            <span
              data-prose
              className={`${SUMMARY_LINE} text-sm max-sm:text-base`}
            >
              {summary}
            </span>
            {rule.description === undefined || expanded ? null : (
              <span
                data-prose
                className={`text-base-content/60 ${SUMMARY_LINE} text-xs max-sm:text-base`}
              >
                {rule.description}
              </span>
            )}
          </span>
        </button>

        {disabled ? null : (
          <div className="flex items-center gap-2 sm:contents">
            <div className="join">
              <button
                type="button"
                className={`${ICON_BUTTON} join-item`}
                aria-label="Move earlier"
                disabled={position === 1}
                onClick={() => {
                  onChange(moveRule(document, list, id, -1));
                }}
              >
                <ArrowUpIcon />
              </button>
              <button
                type="button"
                className={`${ICON_BUTTON} join-item`}
                aria-label="Move later"
                disabled={position === total}
                onClick={() => {
                  onChange(moveRule(document, list, id, 1));
                }}
              >
                <ArrowDownIcon />
              </button>
            </div>
            <button
              type="button"
              className={`${ICON_BUTTON} text-error tooltip`}
              data-tip="Delete rule"
              aria-label="Delete rule"
              onClick={() => {
                onChange(removeRule(document, list, id));
              }}
            >
              <TrashIcon />
            </button>
          </div>
        )}
      </div>

      {expanded ? (
        <div className="mt-3 flex flex-col gap-3">
          <code className="text-base-content/60 font-mono text-xs">{id}</code>

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
      ) : null}
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
