/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The layout components' icons and mobile sizing, asserted from their
 * server-rendered markup.
 *
 * Rendered with `renderToStaticMarkup` rather than a DOM, because everything under
 * test is presentational: what is asserted is that each component carries the
 * intended octicon (by its `octicon-*` class), that decorative icons are hidden from
 * assistive technology, that icon-only controls still say what they do in words,
 * and that the pieces every page is built from ask for wrapping, mobile padding
 * and 44px touch targets below `sm`. Whether the browser then honours those is
 * measured at a real viewport by `e2e/tests/responsive.spec.ts`.
 *
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import {
  CopyableValue,
  DetailList,
  DetailRow,
  EmptyState,
  ErrorAlert,
  InfoAlert,
  Loading,
  PageHeader,
  Panel,
  ShownOnce,
} from "./layout.js";

describe("EmptyState", () => {
  const markup = renderToStaticMarkup(
    <EmptyState title="No endpoints yet" description="Create one." />,
  );

  it("shows a muted inbox icon above the message", () => {
    expect(markup).toContain("octicon-inbox");
  });

  it("hides the icon from assistive technology", () => {
    // The icon decorates the words beside it; it must not be announced.
    expect(markup).toContain('aria-hidden="true"');
  });

  it("narrows its padding below sm so the placeholder fits 360px", () => {
    expect(markup).toContain("max-sm:px-4");
    expect(markup).toContain("max-sm:py-8");
  });

  it("reads its explanation at 16px below sm", () => {
    // An empty list is the first thing a new operator sees, and the sentence
    // saying what the missing thing is is prose rather than annotation.
    expect(markup).toContain("max-w-md text-sm max-sm:text-base");
  });
});

describe("PageHeader", () => {
  const markup = renderToStaticMarkup(
    <PageHeader
      title="Clients"
      description="Apps registered on this endpoint."
      actions={
        <button type="button" className="btn">
          Register client
        </button>
      }
    />,
  );

  it("wraps a title with no break opportunity in it", () => {
    // Endpoint and tenant names reach these headings verbatim, and a long
    // unbroken one would otherwise widen the page rather than the heading.
    expect(markup).toContain("tracking-tight break-words");
  });

  it("lets the title block shrink", () => {
    // `break-words` alone is not enough inside a flex row: the item's automatic
    // minimum size is still its longest word, so it refuses to shrink and the
    // header widens instead of wrapping.
    expect(markup).toContain('<div class="min-w-0">');
  });

  it("wraps the description", () => {
    // Matched on the description's own paragraph rather than on a class pair, so
    // that adding a size class between the two does not read as losing the wrap.
    expect(markup).toMatch(/<p class="[^"]*max-w-2xl[^"]*break-words"/u);
  });

  it("reads the description at 16px below sm", () => {
    // The sentence under a page title is the page's own prose, and FR-004's
    // floor covers prose. The desktop's 14px is untouched.
    expect(markup).toContain("text-sm max-sm:text-base break-words");
  });

  it("gives the action row the full width below sm", () => {
    // Wrapped onto its own line under the title, a row of buttons that is not
    // full width leaves its contents squeezed against the trailing edge.
    expect(markup).toContain("flex max-sm:w-full flex-wrap gap-2");
  });

  it("reads its action buttons at 16px below sm", () => {
    // A header's actions are `btn-sm`, which daisyUI renders at 12px. Matched
    // in its escaped form: React escapes the `&` of an arbitrary variant.
    expect(markup).toContain("max-sm:[&amp;_.btn]:text-base");
  });
});

describe("Panel", () => {
  const markup = renderToStaticMarkup(
    <Panel
      title="Settings"
      description="What this endpoint issues."
      actions={
        <button type="button" className="btn">
          Save
        </button>
      }
    >
      <p>body</p>
    </Panel>,
  );

  it("narrows the card's padding below sm", () => {
    // daisyUI's card body is 24px either side; on a 360px viewport inside a
    // padded main area that is a third of the width spent on margins.
    expect(markup).toContain("card-body max-sm:p-4");
  });

  it("gives the action row the full width below sm", () => {
    expect(markup).toContain("flex max-sm:w-full flex-wrap gap-2");
  });

  it("reads every button inside it at 16px below sm", () => {
    // `btn-xs`, the smallest of them, is 11px - and the console scatters more
    // than a dozen through panel bodies, so the rule lives on the body.
    expect(markup).toContain("max-sm:[&amp;_.btn]:text-base");
  });

  it("lets the title block shrink", () => {
    expect(markup).toContain('<div class="min-w-0">');
  });

  it("restores 16px as the body size inside the card below sm", () => {
    // daisyUI's card body sets its own font size (`--card-fs`, 0.875rem), so
    // every panel in the console renders its body text at 14px however the
    // page is written. Below `sm` the custom property is put back to 1rem, so
    // text that asks for no size of its own reads at 16px.
    expect(markup).toContain("max-sm:[--card-fs:1rem]");
  });

  it("reads the description at 16px below sm", () => {
    expect(markup).toContain("text-sm max-sm:text-base break-words");
  });
});

describe("Loading", () => {
  it("reads its label at 16px below sm", () => {
    // A status message: the constitution requires it be perceivable, and 14px
    // beside a spinner on a phone is the least perceivable text on the page.
    const markup = renderToStaticMarkup(<Loading label="Checking…" />);
    expect(markup).toContain("text-sm max-sm:text-base");
  });
});

describe("DetailRow", () => {
  const markup = renderToStaticMarkup(
    <DetailList>
      <DetailRow label="Issuer">
        https://signet.example.org/t/demo/e/pathling
      </DetailRow>
    </DetailList>,
  );

  it("wraps a value with no break opportunity in it", () => {
    // Issuers, JWKS URLs and key identifiers all land here, and none of them
    // has a space in it to break at. `min-w-0` for the same reason as the page
    // header: a grid item's automatic minimum is its longest word.
    expect(markup).toContain("min-w-0 text-sm break-words");
  });
});

describe("ErrorAlert", () => {
  const markup = renderToStaticMarkup(<ErrorAlert message="It broke" />);

  it("carries the error icon", () => {
    expect(markup).toContain("octicon-x-circle");
  });

  it("still carries the message", () => {
    expect(markup).toContain("It broke");
  });

  it("lets its message shrink and wrap beside the icon", () => {
    // An alert reporting a rejected redirect URI carries the URI in it. Without
    // somewhere to break, the flex item refuses to shrink and the page widens.
    expect(markup).toContain("min-w-0 break-words");
  });

  it("reads at 16px below sm", () => {
    // daisyUI's alert sets 14px of its own, so the size has to go on the alert
    // rather than on what is inside it. An alert is the reason a page stopped
    // doing what was asked of it, which makes it the last thing to shrink.
    expect(markup).toContain("alert alert-error max-sm:text-base");
  });
});

describe("InfoAlert", () => {
  it("carries the info icon", () => {
    const markup = renderToStaticMarkup(<InfoAlert>Saved.</InfoAlert>);
    expect(markup).toContain("octicon-info");
  });

  it("lets its message shrink and wrap beside the icon", () => {
    const markup = renderToStaticMarkup(<InfoAlert>Saved.</InfoAlert>);
    expect(markup).toContain("min-w-0 break-words");
  });

  it("reads at 16px below sm", () => {
    const markup = renderToStaticMarkup(<InfoAlert>Saved.</InfoAlert>);
    expect(markup).toContain("alert alert-info max-sm:text-base");
  });
});

describe("ShownOnce", () => {
  const markup = renderToStaticMarkup(
    <ShownOnce title="Client secret" value="s3cret" />,
  );

  it("carries the warning icon", () => {
    expect(markup).toContain("octicon-alert");
  });

  it("reads its title at 16px below sm", () => {
    expect(markup).toContain(
      "alert alert-warning items-start max-sm:text-base",
    );
  });

  it("reads its warning at 16px below sm", () => {
    // The one sentence in the product that has to be read before the reader
    // navigates away, because what it is about cannot be recovered.
    expect(markup).toContain("mt-1 mb-2 text-sm max-sm:text-base");
  });
});

describe("CopyableValue", () => {
  const markup = renderToStaticMarkup(<CopyableValue value="abc" />);

  it("shows a copy icon instead of the word", () => {
    expect(markup).toContain("octicon-copy");
    // Icon-only: the word "Copy" must not appear as button text. It still
    // appears in the accessible name, so assert on the element text only.
    expect(markup).not.toMatch(/>Copy</u);
  });

  it("keeps an accessible name on the icon-only button", () => {
    expect(markup).toContain('aria-label="Copy"');
  });

  it("names the value in the accessible name when labelled", () => {
    const labelled = renderToStaticMarkup(
      <CopyableValue value="abc" label="Issuer" />,
    );
    expect(labelled).toContain('aria-label="Copy Issuer"');
  });

  it("gives the icon-only button a 44px touch target below sm", () => {
    // `btn-xs` is 24px square, which is the smallest control in the console and
    // the one most often reached for on a phone.
    expect(markup).toContain("max-sm:min-h-11");
    expect(markup).toContain("max-sm:min-w-11");
  });
});
