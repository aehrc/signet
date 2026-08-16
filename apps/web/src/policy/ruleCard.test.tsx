/**
 * The rule card's icons, asserted from server-rendered markup.
 *
 * The card's controls were previously text glyphs (↑, ↓, ▲, ▼) and a worded
 * Delete button; these tests pin the octicon replacements, and that the icon-only
 * delete still names its action for assistive technology and on hover.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { RuleCard } from "./ruleCard.js";

import type { AnyRule } from "./rules.js";
import type { PolicyDocument } from "@signet/core";

const rule: AnyRule = { id: "grant-abc123", match: "patient/*.r", allow: true };

const document: PolicyDocument = {
  version: 1,
  scopeGrants: [rule],
  claimRules: [],
  contextRules: [],
  defaults: { accessTokenTtl: 300, refreshTokenTtl: 3600 },
};

/** Renders the card with the given expansion state and edit permission. */
function render(expanded: boolean, disabled = false): string {
  return renderToStaticMarkup(
    <RuleCard
      list="scopeGrants"
      document={document}
      rule={rule}
      position={1}
      total={2}
      summary="Allow patient reads"
      enabled
      disabled={disabled}
      expanded={expanded}
      onToggle={() => undefined}
      onChange={() => undefined}
    >
      <p>fields</p>
    </RuleCard>,
  );
}

describe("RuleCard", () => {
  it("draws the reorder buttons with arrow octicons", () => {
    const markup = render(false);
    expect(markup).toContain("octicon-arrow-up");
    expect(markup).toContain("octicon-arrow-down");
    expect(markup).toContain('aria-label="Move earlier"');
    expect(markup).toContain('aria-label="Move later"');
  });

  it("draws the delete button as an icon-only trash button", () => {
    const markup = render(false);
    expect(markup).toContain("octicon-trash");
    expect(markup).not.toMatch(/>Delete</u);
    expect(markup).toContain('aria-label="Delete rule"');
    // A tooltip repeats the name for sighted readers, since there is no text.
    expect(markup).toContain('data-tip="Delete rule"');
  });

  it("points the expansion chevron down when collapsed and up when expanded", () => {
    expect(render(false)).toContain("octicon-chevron-down");
    expect(render(true)).toContain("octicon-chevron-up");
  });

  it("shows no edit controls when editing is disabled", () => {
    const markup = render(false, true);
    expect(markup).not.toContain("octicon-trash");
    expect(markup).not.toContain("octicon-arrow-up");
  });
});
