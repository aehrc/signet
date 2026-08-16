/**
 * The choice list's mobile sizing, asserted from its server-rendered markup.
 *
 * This list is how a person picks a persona to continue as, or the record an
 * authorization is about, so its entries are the controls a phone user taps to
 * get through the flow. daisyUI's menu entry is 33px tall, which is under the
 * 44px a thumb needs, and its label is 14px.
 *
 * Static markup can hold that an entry asks for 44px; `e2e/tests/responsive.spec.ts`
 * measures that the browser gives it.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { ChoiceList } from "./choiceList.js";

/** Two choices, one of which carries a long identifier as its detail. */
const CHOICES = [
  { value: "persona-1", label: "Pat Patient", detail: "Patient/pat-9" },
  {
    value: "persona-2",
    label: "persona-target",
    detail: "1786875371183-463673-a-very-long-unbroken-identifier",
  },
] as const;

describe("ChoiceList", () => {
  const markup = renderToStaticMarkup(
    <ChoiceList
      choices={CHOICES}
      disabled={false}
      onChoose={() => undefined}
    />,
  );

  it("offers a 44px tall target on each entry below sm", () => {
    expect(markup).toContain("max-sm:min-h-11");
  });

  it("reads its labels at 16px below sm", () => {
    expect(markup).toContain("max-sm:text-base");
  });

  it("lets a long detail wrap rather than widen the card", () => {
    // An identifier is one word with nothing to break at, so it needs both a
    // break opportunity and a shrinkable box to reach it. `break-words` rather
    // than `break-all`, so a short identifier is not split mid-word.
    expect(markup).toContain("break-words");
    expect(markup).toContain("min-w-0");
  });

  it("renders nothing when there is nothing to choose between", () => {
    expect(
      renderToStaticMarkup(
        <ChoiceList choices={[]} disabled={false} onChoose={() => undefined} />,
      ),
    ).toBe("");
  });
});
