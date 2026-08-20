/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The form controls' mobile sizing, asserted from their server-rendered markup.
 *
 * One defect drives most of this file: a mobile browser zooms the page when a
 * focused input's text is under 16px, and every control here inherits daisyUI's
 * 14px. The zoom is not undone when the field is left, so a form filled on a
 * phone ends up sideways-scrolled through no action of the reader's. The fix is
 * a responsive bump, so the desktop's denser rendering is untouched - which is
 * why each assertion below is on a `max-sm:` class rather than on a plain one.
 *
 * The remaining assertions are touch targets, for the same reason and with the
 * same division of labour: static markup can hold that a control asks for 44px,
 * and `e2e/tests/responsive.spec.ts` measures that the browser gives it.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  CheckboxField,
  FormFooter,
  ListField,
  SaveRow,
  SelectField,
  SubmitButton,
  TextAreaField,
  TextField,
} from "./fields.js";

/** Every field renders the same legend frame, so it is asserted once. */
describe("a field's legend", () => {
  const markup = renderToStaticMarkup(
    <TextField label="Client identifier" value="" onChange={() => undefined} />,
  );

  it("is a fieldset legend that reads at 16px below sm", () => {
    expect(markup).toContain(
      "fieldset-legend whitespace-normal max-sm:text-base",
    );
  });

  it("names the control from the legend", () => {
    expect(markup).toMatch(/<legend id="([^"]+)"/);
    const legendId = /<legend id="([^"]+)"/.exec(markup)?.[1];
    expect(markup).toContain(`aria-labelledby="${legendId ?? ""}"`);
  });
});

/**
 * The hint and the error are the two sentences a field can carry, and both are
 * prose the reader has to act on: one says what to type, the other says why what
 * was typed was refused. Both are 12px on the desktop, which is the smallest text
 * in any form.
 */
describe("a field's hint and error", () => {
  const markup = renderToStaticMarkup(
    <TextField
      label="Client identifier"
      value=""
      onChange={() => undefined}
      hint="Lower case, no spaces."
      error="Already taken."
    />,
  );

  it("reads the hint at 16px below sm", () => {
    expect(markup).toContain("mt-1 text-xs max-sm:text-base");
  });

  it("reads the error at 16px below sm", () => {
    expect(markup).toContain("text-error mt-1 text-xs max-sm:text-base");
  });
});

describe("SaveRow", () => {
  const markup = renderToStaticMarkup(
    <SaveRow label="Save" hasChanges={false} pending={false} />,
  );

  it("reads the reason the button is disabled at 16px below sm", () => {
    // Visibility of system status: the only thing on screen saying why a press
    // would do nothing, and the smallest text beside it.
    expect(markup).toContain("text-xs max-sm:text-base");
  });
});

describe("TextField", () => {
  const markup = renderToStaticMarkup(
    <TextField
      label="Client identifier"
      value="stub-app"
      onChange={() => undefined}
    />,
  );

  it("renders its input at 16px below sm, so the browser does not zoom it", () => {
    expect(markup).toContain(
      "input input-bordered w-full max-sm:min-h-11 max-sm:text-base",
    );
  });

  it("offers a 44px tall target below sm", () => {
    // daisyUI's input is 40px tall, which is a field a thumb misses the edge of.
    expect(markup).toContain("max-sm:min-h-11");
  });

  it("still fills the width it is given", () => {
    expect(markup).toContain("w-full");
  });
});

describe("TextAreaField", () => {
  it("renders at 16px below sm", () => {
    const markup = renderToStaticMarkup(
      <TextAreaField
        label="Redirect URIs"
        value=""
        onChange={() => undefined}
      />,
    );
    expect(markup).toContain(
      "textarea textarea-bordered w-full max-sm:text-base",
    );
  });

  it("keeps 16px below sm even where the desktop uses 12px monospace", () => {
    // The monospace variant is what {@link ListField} renders, and it is the
    // smallest text in any form: 12px, on the field most often pasted into.
    const markup = renderToStaticMarkup(
      <ListField label="Redirect URIs" value="" onChange={() => undefined} />,
    );
    expect(markup).toContain("font-mono text-xs");
    // Tailwind emits variant utilities after unvariant ones, so the responsive
    // size wins inside the media query without the desktop size being dropped.
    expect(markup).toContain("max-sm:text-base");
  });
});

describe("SelectField", () => {
  const markup = renderToStaticMarkup(
    <SelectField
      label="Status"
      value="active"
      options={[{ value: "active", label: "Active" }]}
      onChange={() => undefined}
    />,
  );

  it("renders at 16px below sm", () => {
    expect(markup).toContain(
      "select select-bordered w-full max-sm:min-h-11 max-sm:text-base",
    );
  });

  it("offers a 44px tall target below sm", () => {
    expect(markup).toContain("max-sm:min-h-11");
  });
});

describe("CheckboxField", () => {
  const markup = renderToStaticMarkup(
    <CheckboxField
      label="This is a persona"
      checked={false}
      onChange={() => undefined}
      hint="Personas stand in for a real account during a demonstration."
    />,
  );

  it("offers a 44px tall target below sm", () => {
    // The box itself stays small; the label is what is tapped, so the label is
    // what has to be big enough to hit.
    expect(markup).toContain("max-sm:min-h-11");
  });

  it("reads its label at 16px below sm", () => {
    expect(markup).toContain("max-sm:text-base");
  });

  it("reads its hint at 16px below sm", () => {
    expect(markup).toContain("ml-7 text-xs max-sm:text-base");
  });
});

describe("SubmitButton", () => {
  const markup = renderToStaticMarkup(
    <SubmitButton>Save settings</SubmitButton>,
  );

  it("offers a 44px touch target below sm", () => {
    // daisyUI's small button is 32px tall, so the responsive minimum is what
    // keeps the thumb target at 44px on a phone.
    expect(markup).toContain("btn btn-sm btn-primary max-sm:min-h-11");
  });

  it("reads its label at 16px below sm", () => {
    // Sized on the button itself as well as by the panel around it, because a
    // form is not always inside a panel.
    expect(markup).toContain("max-sm:text-base");
  });
});

describe("FormFooter", () => {
  const markup = renderToStaticMarkup(
    <FormFooter
      error={null}
      issues={{}}
      pending={false}
      submitLabel="Register"
      onCancel={() => undefined}
    />,
  );

  it("wraps its buttons rather than letting them overflow", () => {
    expect(markup).toContain("flex flex-wrap gap-2");
  });

  it("offers a 44px touch target on Cancel below sm", () => {
    expect(markup).toContain("btn btn-ghost max-sm:min-h-11");
  });

  it("reads Cancel at 16px below sm", () => {
    expect(markup).toContain("btn btn-ghost max-sm:min-h-11 max-sm:text-base");
  });
});
