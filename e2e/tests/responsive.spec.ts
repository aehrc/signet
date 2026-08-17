/**
 * What "renders well on a phone" means, as assertions.
 *
 * This file runs only under the `mobile` project, at the 360x780 viewport the
 * feature is specified against. The two claims it exists to prove are layout
 * facts, and a layout fact is only measurable in a browser that has laid the
 * page out: no unit test can tell you whether a page scrolls sideways.
 *
 * Horizontal overflow is asserted as `scrollWidth <= clientWidth` on the root
 * element and on the body, which is the definition of the page scrolling
 * sideways and needs no knowledge of the page under test. It deliberately says
 * nothing about inner containers: a table, a code block or a diff is *allowed*
 * to scroll inside itself, and an assertion that walked every element's
 * bounding box would report those as failures by design.
 *
 * Author: John Grimes
 */

import { expect, test } from "@playwright/test";

import { openPasskeyDialog } from "../support/console.js";
import {
  choosePatient,
  completedTokenResponse,
  decideConsent,
  signIn,
  startLaunch,
} from "../support/launch.js";
import {
  CONSOLE_STORAGE_STATE,
  ISSUER,
  SEED,
  SIGNET,
} from "../support/stack.js";

import type { Locator, Page } from "@playwright/test";

/**
 * The smallest tap target a touch surface may offer, in CSS pixels.
 *
 * 44x44 is the WCAG 2.2 AAA target size and Apple's Human Interface Guidelines
 * minimum, and is the figure FR-003 fixed.
 */
const MINIMUM_TAP_TARGET = 44;

/**
 * The smallest text a control may render below the small breakpoint, in CSS pixels.
 *
 * 16 is not a readability figure, it is a browser threshold: mobile Safari and
 * Chrome for Android zoom the page when they focus a field whose text is smaller
 * than this, and neither zooms back out when the field is left. FR-004 fixed it.
 *
 * What the floor covers, and what it deliberately does not, is written down in
 * `apps/web/src/components/layout.tsx`. The short of it: text the reader enters,
 * the inherited body size, and running prose. Not the annotation layer - card
 * field labels, badges, timestamps, monospace identifiers and code - which the
 * approved wireframes size at 0.7rem and 0.85rem. The first is measured by
 * {@link expectNoAutoZoom}, because it is the one with a mechanical consequence;
 * the third by {@link expectProseReadable}, because a reading nothing checks is a
 * reading that drifts.
 */
const MINIMUM_CONTROL_TEXT = 16;

/** How wide an element's content is, against how wide the element itself is. */
interface Extent {
  readonly scrollWidth: number;
  readonly clientWidth: number;
}

/**
 * As much of an element as reading its computed font size needs.
 *
 * Reached through the element's own document rather than a bare `getComputedStyle`
 * for the same reason {@link Extent} exists: this package names no DOM library, so
 * the shape the callback relies on is declared where it is used, and typechecked.
 */
interface Styled {
  readonly ownerDocument: {
    readonly defaultView: {
      readonly getComputedStyle: (element: object) => {
        readonly fontSize: string;
      };
    };
  };
}

/**
 * As much of an element as deciding whether it carries text of its own needs.
 *
 * Declared here for the same reason {@link Styled} is: the package names no DOM
 * library, so the shape the callback relies on is written down where it is used.
 */
interface Prose extends Styled {
  readonly childNodes: Iterable<{
    readonly nodeType: number;
    readonly textContent: string | null;
  }>;
}

/**
 * Measures one element's content width against its own width.
 *
 * Read through a locator rather than from `document` in a bare
 * `page.evaluate`, because this package names no DOM library - typing the
 * callback's own parameter is what keeps the measurement checked.
 *
 * @param locator - The element to measure. Must resolve to exactly one node.
 * @returns Its scroll width and client width, in CSS pixels.
 */
async function extentOf(locator: Locator): Promise<Extent> {
  return await locator.evaluate((element: Extent) => ({
    scrollWidth: element.scrollWidth,
    clientWidth: element.clientWidth,
  }));
}

/**
 * Fails when the page body can be scrolled sideways.
 *
 * Both the root element and the body are checked: a child wide enough to push
 * the document out shows up on the root, and a body with its own width or
 * padding overflow shows up on the body, and neither implies the other.
 *
 * @param page - The page to measure, already navigated and settled.
 * @throws {Error} When either element's content is wider than the element.
 * @example
 * ```ts
 * await page.goto(`${SIGNET}/console/t/demo/e/pathling/clients`);
 * await expectNoPageOverflow(page);
 * ```
 */
export async function expectNoPageOverflow(page: Page): Promise<void> {
  const root = await extentOf(page.locator("html"));
  expect(
    root.scrollWidth,
    `the document scrolls sideways at ${String(root.clientWidth)}px`,
  ).toBeLessThanOrEqual(root.clientWidth);

  const body = await extentOf(page.locator("body"));
  expect(
    body.scrollWidth,
    `the body scrolls sideways at ${String(body.clientWidth)}px`,
  ).toBeLessThanOrEqual(body.clientWidth);
}

/**
 * Fails when any visible element matching the selector is too small to tap.
 *
 * Hidden elements are skipped rather than failed: a closed drawer's entries and
 * a dialog that has not been opened have no box to measure, and asserting on
 * them would report a size failure for something nobody can touch. The match
 * itself is asserted to be non-empty, so a selector that has gone stale fails
 * here rather than passing by measuring nothing.
 *
 * @param page - The page to measure, already navigated and settled.
 * @param selector - The interactive elements to sample.
 * @throws {Error} When the selector matches nothing, or when a visible match is under
 *   44x44 CSS pixels.
 * @example
 * ```ts
 * await expectTapTargets(page, ".drawer-side a");
 * ```
 */
export async function expectTapTargets(
  page: Page,
  selector: string,
): Promise<void> {
  const targets = page.locator(selector);
  const count = await targets.count();
  expect(count, `nothing matched ${selector}`).toBeGreaterThan(0);

  for (let index = 0; index < count; index++) {
    const target = targets.nth(index);
    if (!(await target.isVisible())) {
      continue;
    }
    const box = await target.boundingBox();
    const name = (await target.textContent())?.trim() ?? selector;
    expect(box, `${selector} #${String(index)} has no box`).not.toBeNull();
    expect(
      box?.width ?? 0,
      `"${name}" is narrower than ${String(MINIMUM_TAP_TARGET)}px`,
    ).toBeGreaterThanOrEqual(MINIMUM_TAP_TARGET);
    expect(
      box?.height ?? 0,
      `"${name}" is shorter than ${String(MINIMUM_TAP_TARGET)}px`,
    ).toBeGreaterThanOrEqual(MINIMUM_TAP_TARGET);
  }
}

/**
 * Everything a thumb has to hit.
 *
 * Four kinds of control, and the first two are the reason this is not the
 * narrower selector it started as. `a.btn` sampled only the anchors already
 * styled as buttons - the class that was never at risk - and excluded the bare
 * `link` anchor, which is 18px tall and is the *only* navigation on every card
 * in every console list below `sm`. A sampler that cannot match the failing
 * class cannot fail on it, so the requirement it was standing in for was not
 * being held. `a[href]` matches both.
 *
 * `label.btn` is the drawer's hamburger, which is a control rather than a
 * caption. `label:has(input[type='checkbox'])` is a checkbox's tap target: the
 * box itself is deliberately left at 20px and the label wrapped around it is
 * what a thumb aims at, which is the design `fields.tsx` writes down, so the
 * label is the thing worth measuring and the box is not.
 *
 * A field's caption - a bare `label` pointing at an input by `htmlFor` - is
 * deliberately absent. It is a 24px line of text that happens to focus the
 * control when tapped, not a control in its own right, and the control it names
 * is measured through {@link ENTRY_FIELDS}.
 *
 * The one exemption is an anchor inside a paragraph, written as `:not(p a)` so
 * that it exempts the position rather than the element - the same component
 * outside a paragraph is still measured. This is WCAG 2.5.8's own "inline"
 * exception: a target "in a sentence, or whose size is otherwise constrained by
 * the line-height of non-target text". Two anchors are in that position - the
 * portal address inside the requests page's description, and the specification
 * citations inside the policy presets' "Contract:" lines - and giving either a
 * 44px box would break the sentence it sits in rather than make it easier to
 * hit.
 *
 * The text inputs are measured by the same helper through {@link ENTRY_FIELDS},
 * separately, because a field that is too short and a button that is too small
 * are different defects with different fixes and reading one failure should not
 * hide the other.
 */
const CONTROLS =
  "button, a[href]:not(p a), label.btn, label:has(input[type='checkbox'])";

/** The text entry controls on an end-user surface. */
const ENTRY_FIELDS = "input:not([type='checkbox']), select, textarea";

/**
 * Fails when any visible entry control renders text a mobile browser would zoom.
 *
 * Measured rather than asserted on a class, because the class is only a request:
 * `max-sm:text-base` on a control that daisyUI sizes through a more specific
 * selector, or inside a container that sets its own size, is a class that is in
 * the markup and not in the layout. `getComputedStyle` is the only thing that
 * knows which won.
 *
 * A page with no entry controls passes rather than failing. The pages that carry
 * them assert separately, through {@link expectTapTargets}, that the selector
 * matched something, so a selector that goes stale still fails somewhere.
 *
 * @param page - The page to measure, already navigated and settled.
 * @throws {Error} When a visible input, select or textarea renders under 16px.
 * @example
 * ```ts
 * await page.goto(`${ISSUER}/apps`);
 * await expectNoAutoZoom(page);
 * ```
 */
export async function expectNoAutoZoom(page: Page): Promise<void> {
  const fields = page.locator(ENTRY_FIELDS);
  const count = await fields.count();

  for (let index = 0; index < count; index++) {
    const field = fields.nth(index);
    if (!(await field.isVisible())) {
      continue;
    }
    const size = await field.evaluate((element: Styled) =>
      Number.parseFloat(
        element.ownerDocument.defaultView.getComputedStyle(element).fontSize,
      ),
    );
    const name =
      (await field.getAttribute("aria-label")) ??
      (await field.getAttribute("name")) ??
      `${ENTRY_FIELDS} #${String(index)}`;
    expect(
      size,
      `"${name}" renders at ${String(size)}px, which a mobile browser zooms`,
    ).toBeGreaterThanOrEqual(MINIMUM_CONTROL_TEXT);
  }
}

/**
 * Running prose, as a selector.
 *
 * FR-004's floor covers more than the fields a browser zooms, and the reading
 * written in `apps/web/src/components/layout.tsx` says what: prose addressed to
 * the reader - descriptions, hints, empty states, validation and status
 * messages - as against an annotation layer of badges, timestamps, monospace
 * identifiers and the labelled values inside a mobile card, which the approved
 * wireframes fix below 16px on purpose. That reading is only worth writing down
 * if something checks it, so this is where prose lives structurally:
 *
 * - `p`, which this product uses for nothing but prose, less the monospace ones
 *   - a `p` in a monospace face is a value being shown exactly (the rule
 *   builder's pattern preview), which the reading excludes as an identifier.
 * - `li`, for prose that comes as a list: the simulator reports each refused
 *   scope and the reason it was refused as one list item.
 * - `.label-text` and `legend`, the captions above a control and above a group
 *   of them. Not prose in the strict sense, but read the same way and sized the
 *   same way, and `fields.tsx` already raises the shared one - so leaving the
 *   half-dozen written by hand at 14px is a difference with no reason behind it.
 * - `[data-prose]`, for the two lines that cannot be a `p`: a rule card's
 *   summary and its description sit inside the `button` that expands the card,
 *   whose content model admits no paragraph.
 *
 * Measured on the element that carries the text rather than on the text, so a
 * paragraph that sets 12px and holds a `code` child is reported against the
 * paragraph, which is where the class that caused it lives. An element with no
 * text of its own is skipped for the same reason: the picker's choices are
 * `li`s inside a daisyUI menu, which sizes them at 14px, and every word in them
 * is inside a 16px `button` - the `li`'s own size governs nothing, and failing on
 * it would be reporting a number nobody can read.
 *
 * @param page - The page to measure, already navigated and settled.
 * @throws {Error} When visible prose renders under 16px.
 * @example
 * ```ts
 * await page.goto(`${ENDPOINT}/policy`);
 * await expectProseReadable(page);
 * ```
 */
export async function expectProseReadable(page: Page): Promise<void> {
  const passages = page.locator(PROSE);
  const count = await passages.count();

  for (let index = 0; index < count; index++) {
    const passage = passages.nth(index);
    if (!(await passage.isVisible())) {
      continue;
    }
    const measured = await passage.evaluate((element: Prose) => ({
      // 3 is `Node.TEXT_NODE`, spelled as its value because this package names
      // no DOM library and so has no `Node` to read it from.
      carriesText: [...element.childNodes].some(
        (node) => node.nodeType === 3 && (node.textContent ?? "").trim() !== "",
      ),
      size: Number.parseFloat(
        element.ownerDocument.defaultView.getComputedStyle(element).fontSize,
      ),
    }));
    if (!measured.carriesText) {
      continue;
    }
    const text = (await passage.textContent())?.trim() ?? "";
    expect(
      measured.size,
      `"${text.slice(0, 60)}" renders at ${String(measured.size)}px, under the 16px floor`,
    ).toBeGreaterThanOrEqual(MINIMUM_CONTROL_TEXT);
  }
}

/** Where prose lives in this product's markup. See {@link expectProseReadable}. */
const PROSE =
  "p:not(.font-mono), li:not(.font-mono), .label-text, legend, [data-prose]";

/**
 * Asserts a page is readable and operable at the mobile viewport.
 *
 * @param page - The page to measure, already navigated and settled.
 * @throws {Error} When the page scrolls sideways or carries an undersized control.
 */
async function expectUsableOnAPhone(page: Page): Promise<void> {
  await expectNoPageOverflow(page);
  await expectTapTargets(page, CONTROLS);
  await expectNoAutoZoom(page);
  await expectProseReadable(page);
}

test.describe("end-user surfaces", () => {
  test("carry a SMART launch through to a token at 360px", async ({ page }) => {
    // ---- Sign in ------------------------------------------------------------
    await startLaunch(page);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expectUsableOnAPhone(page);
    // A field under 44px is a field a thumb misses, and one whose text is under
    // 16px is one mobile Safari zooms into and never zooms back out of.
    await expectTapTargets(page, ENTRY_FIELDS);
    await signIn(page);

    // ---- Pick the record ----------------------------------------------------
    await expect(
      page.getByRole("heading", { name: "Choose a record" }),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
    await choosePatient(page, "pat-9");

    // ---- Consent ------------------------------------------------------------
    await expect(
      page.getByRole("heading", { name: "Allow access?" }),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
    // Both decisions are on screen, not just the one the layout had room for.
    await expect(
      page.getByRole("button", { name: "Allow", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Deny", exact: true }),
    ).toBeVisible();
    // Every scope the app asked for is readable, technical string included.
    const scopes = page.locator("main ul li, .card-body ul li");
    expect(await scopes.count()).toBeGreaterThan(0);
    await decideConsent(page, "Allow");

    // ---- Back at the app ----------------------------------------------------
    const tokenResponse = await completedTokenResponse(page);
    expect(tokenResponse["patient"]).toBe("pat-9");

    // ---- The manage page, now that there is something on it -----------------
    // A separate credential from the one just used: the management endpoint has
    // its own session, and its own rate-limit allowance, so signing in here
    // costs nothing from the interaction budget.
    await page.goto(`${ISSUER}/manage`);
    await expect(
      page.getByRole("heading", { name: "Your app access" }),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
    await page.getByLabel("Username").fill(SEED.username);
    await page.getByLabel("Password").fill(SEED.password);
    await page.getByRole("button", { name: "Sign in" }).click();

    // The grant the journey above just created, with its withdrawal control.
    await expect(
      page.getByRole("button", { name: "Withdraw access" }).first(),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
  });

  test("offer the developer portal at 360px", async ({ page }) => {
    await page.goto(`${ISSUER}/apps`);
    await expect(
      page.getByRole("heading", { name: "Register an app" }),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });
});

/** The endpoint every endpoint-scoped console route below hangs off. */
const ENDPOINT = `${SIGNET}/console/t/demo/e/pathling`;

/**
 * The console routes swept at the mobile viewport, and how each says it arrived.
 *
 * A heading rather than a `load` event, because every one of these pages fetches
 * what it shows: measuring a page whose panels are still spinners would report
 * that an empty column fits, which is true and worthless.
 *
 * The policy and launch pages are deliberately absent. They are the feature's
 * third story - the dense tools - and sweeping them here would report their
 * defects against this story's fixes.
 */
const CONSOLE_ROUTES: readonly {
  readonly name: string;
  readonly url: string;
  readonly heading: string;
}[] = [
  {
    name: "the endpoint list",
    url: `${SIGNET}/console/t/demo`,
    heading: "Endpoints",
  },
  {
    name: "the audit trail",
    url: `${SIGNET}/console/t/demo/audit`,
    heading: "Audit",
  },
  {
    name: "tenant settings",
    url: `${SIGNET}/console/t/demo/settings`,
    heading: "Tenant settings",
  },
  { name: "the endpoint overview", url: ENDPOINT, heading: "Integration" },
  { name: "the client list", url: `${ENDPOINT}/clients`, heading: "Clients" },
  {
    name: "a client's detail",
    url: `${ENDPOINT}/clients/stub-app`,
    heading: "Registration",
  },
  { name: "the user list", url: `${ENDPOINT}/users`, heading: "Users" },
  {
    name: "the signing keys",
    url: `${ENDPOINT}/keys`,
    heading: "Signing keys",
  },
  {
    name: "the identity settings",
    url: `${ENDPOINT}/identity`,
    heading: "Identity provider",
  },
  {
    name: "the trust settings",
    url: `${ENDPOINT}/trust`,
    heading: "Trust and tickets",
  },
  {
    // Populated rather than empty, and that is the whole reason it is worth
    // sweeping. The seed files two requests with long, entirely legal values -
    // see `scripts/seedStack.mjs` - because this route used to be measurable only
    // in its empty state: the endpoint accepted no self-serve requests, so no
    // request could exist, and an empty queue fits any viewport.
    name: "the registration requests",
    url: `${ENDPOINT}/requests`,
    heading: "Registration requests",
  },
];

/** The console's own navigation entries, in the drawer the hamburger opens. */
const DRAWER_ENTRIES = ".drawer-side a";

/**
 * Opens the navigation drawer and waits for it to be on screen.
 *
 * The drawer is a checkbox and a label, so it has no ARIA state to wait on; the
 * first entry becoming visible is what says it has slid in.
 *
 * @param page - A console page at a viewport below the drawer's `lg` breakpoint.
 * @returns The drawer's navigation entries, for the caller to act on.
 */
async function openDrawer(page: Page): Promise<Locator> {
  await page.getByLabel("Open navigation").click();
  const entries = page.locator(DRAWER_ENTRIES);
  await expect(entries.first()).toBeVisible();
  return entries;
}

test.describe("console surfaces", () => {
  // The saved administrator session, so none of this spends an end-user sign-in
  // from the per-minute budget the suite's config documents.
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  for (const route of CONSOLE_ROUTES) {
    test(`fits ${route.name} on a phone`, async ({ page }) => {
      await page.goto(route.url);
      await expect(
        page.getByRole("heading", { name: route.heading }).first(),
      ).toBeVisible();

      await expectUsableOnAPhone(page);

      // Again with the drawer open: an overlay is laid out over the page rather
      // than inside it, so a drawer wider than the viewport is a defect the
      // closed measurement cannot see.
      await openDrawer(page);
      await expectNoPageOverflow(page);
      await expectTapTargets(page, DRAWER_ENTRIES);
    });
  }

  test("opens, navigates and closes the console drawer by touch", async ({
    page,
  }) => {
    await page.goto(`${SIGNET}/console/t/demo`);
    await expect(
      page.getByRole("heading", { name: "Endpoints" }),
    ).toBeVisible();

    // Closed to begin with: below `lg` the sidebar is an overlay, not a column.
    await expect(page.locator(DRAWER_ENTRIES).first()).toBeHidden();

    const entries = await openDrawer(page);
    await entries.filter({ hasText: "Audit" }).click();

    // Navigating closes it, so the page arrived at is the page on screen.
    await expect(page.getByRole("heading", { name: "Audit" })).toBeVisible();
    await expect(page.locator(DRAWER_ENTRIES).first()).toBeHidden();

    // And the shaded area beside the drawer closes it without navigating
    // anywhere. Aimed to the right of the 256px drawer rather than at the
    // overlay's centre: the overlay covers the whole viewport, so its middle is
    // behind the drawer, which is not somewhere a thumb could reach it.
    await openDrawer(page);
    await page
      .getByLabel("Close navigation")
      .click({ position: { x: 320, y: 400 } });
    await expect(page.locator(DRAWER_ENTRIES).first()).toBeHidden();
    await expect(page).toHaveURL(`${SIGNET}/console/t/demo/audit`);
  });

  test("renders the console's clients as labelled cards on a phone", async ({
    page,
  }) => {
    await page.goto(`${ENDPOINT}/clients`);
    await expect(page.getByRole("heading", { name: "Clients" })).toBeVisible();

    // The table is what a desktop shows, and at 360px it must not be what is on
    // screen: a five-column table here is how a column ends up off the edge.
    await expect(page.locator("table")).toBeHidden();

    // One card per client, each titled by the first column and carrying every
    // other column as a labelled value - including "Grants", which the desktop
    // table used to drop below `sm` (SC-003).
    const card = page
      .getByRole("listitem")
      .filter({ hasText: "Stub SMART app" });
    await expect(card).toBeVisible();
    await expect(
      card.getByRole("link", { name: "Stub SMART app" }),
    ).toBeVisible();
    await expect(card.getByText("Authentication")).toBeVisible();
    await expect(card.getByText("Grants")).toBeVisible();
    await expect(card.getByText("Status")).toBeVisible();
    await expect(card.getByText("authorization_code")).toBeVisible();

    // And the row's action still works from the card: tapping the title opens
    // the client, which is the one thing a row offers (FR-006).
    await card.getByRole("link", { name: "Stub SMART app" }).click();
    await expect(
      page.getByRole("heading", { name: "Stub SMART app" }),
    ).toBeVisible();
  });

  test("keeps a signing key's own action operable in its card", async ({
    page,
  }) => {
    // A per-row button rather than a link: the keys list is the only console list
    // whose action is a control rather than a navigation, and a button too small
    // to hit is the failure this asserts against (FR-003, FR-006).
    await page.goto(`${ENDPOINT}/keys`);
    await expect(
      page.getByRole("heading", { name: "Signing keys" }),
    ).toBeVisible();
    await expect(page.locator("table")).toBeHidden();

    const card = page
      .getByRole("listitem")
      .filter({ hasText: "active" })
      .first();
    await expect(card.getByText("Created")).toBeVisible();
    await expect(card.getByRole("button", { name: "Retire" })).toBeVisible();
    await expectTapTargets(page, CONTROLS);
  });

  test("fits a user's detail page on a phone", async ({ page }) => {
    // Reached by tapping the card rather than by address: an end user's
    // identifier is minted by the seed, so there is no URL to write down here.
    await page.goto(`${ENDPOINT}/users`);
    await page.getByRole("link", { name: "Dr Casey Clinician" }).click();
    await expect(page.getByLabel("Display name")).toHaveValue(
      "Dr Casey Clinician",
    );
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });

  test("holds a registration request's long values on a phone", async ({
    page,
  }) => {
    // The sweep above measures the page; this measures the values on it, because
    // "the body does not scroll" and "the launch URI is readable" are different
    // claims and a page can satisfy the first by clipping the second (FR-007).
    await page.goto(`${ENDPOINT}/requests`);
    const pending = page
      .locator("section.card")
      .filter({ hasText: SEED.longRequestName });

    // The contact address, the launch URI and the note: one unbroken word each,
    // and each the width of the page on its own before it was given somewhere to
    // break. Measured on the element, so a failure names the value rather than
    // the document.
    //
    // Found by a label anchored to the start of the pair, rather than by its text
    // anywhere: `getByText` matches a case-insensitive substring, and the note
    // this request carries contains the phrase "launch URI".
    for (const label of [
      /^Contact/,
      /^Launch URI/,
      /^What they said it is for/,
    ]) {
      const value = pending
        .locator("dl > div")
        .filter({ hasText: label })
        .locator("dd");
      await expect(value).toBeVisible();
      await expectWithinViewport(page, value);
    }

    // One chip holding a 158-character redirect URI. `Chips` wraps between chips,
    // which does nothing for a list of one long one - so the chip itself has to
    // break, and this is the assertion that says so.
    const redirectUris = pending
      .locator("dl > div")
      .filter({ hasText: /^Redirect URIs/ })
      .locator("code");
    await expectWithinViewport(page, redirectUris.last());

    // And the decided half of the page, whose only content is a refusal the seed
    // filed: the reviewer's note is a paragraph somebody has to read (FR-012).
    const decided = panelTitled(page, "Decided");
    await expect(decided.getByText(SEED.refusedRequestName)).toBeVisible();
    await expect(decided.getByText("Refused for now")).toBeVisible();
    await expectUsableOnAPhone(page);
  });

  test("fits the passkey dialog on a phone", async ({ page }) => {
    // No test opened this dialog at a mobile viewport, which is why nothing saw
    // that its close button came out 42px wide. It is an overlay rather than a
    // route, so the sweep cannot reach it: it has to be opened.
    //
    // The list is answered by a fixture rather than by the account's own
    // passkeys, and for a reason the empty state cannot cover: the row's remove
    // control is an icon and nothing else, and the console session used here
    // holds no passkey - registering one needs a virtual authenticator and would
    // put this file in the business of `passkeys.spec.ts`.
    await page.route("**/api/v1/account/passkeys", async (route) => {
      await route.fulfill({
        json: {
          passkeys: [
            {
              id: "11111111-2222-3333-4444-555555555555",
              name: "Work laptop",
              createdAt: "2026-08-01T09:15:00.000Z",
              lastUsedAt: "2026-08-14T22:41:00.000Z",
            },
            {
              id: "66666666-7777-8888-9999-000000000000",
              name: "Personal phone, enrolled at the Brisbane connectathon",
              createdAt: "2026-08-02T01:05:00.000Z",
              lastUsedAt: null,
            },
          ],
        },
      });
    });

    await page.goto(`${SIGNET}/console/t/demo`);
    await openPasskeyDialog(page);
    await expect(page.getByText("Work laptop")).toBeVisible();

    await expectUsableOnAPhone(page);

    // Named individually as well, because the two that were wrong are the two
    // with no text in them, and a sweep that skipped them would still pass.
    await expectTapTargets(page, ".modal-box button[aria-label='Close']");
    await expectTapTargets(page, ".modal-box [aria-label^='Remove ']");
  });

  test("fits the tenant list shown for a tenant you do not belong to", async ({
    page,
  }) => {
    // The one console screen the route sweep cannot reach, because it is what a
    // tenant slug that resolves to no membership produces rather than a route
    // anybody navigates to. Its tenant list is also the chooser a member of
    // several tenants lands on, which the stack seeds nobody to be - so this is
    // the only way to measure that list in a browser at all.
    await page.goto(`${SIGNET}/console/t/not-a-tenant`);
    await expect(
      page.getByText("You are not a member of that tenant"),
    ).toBeVisible();
    await expect(page.getByRole("link", { name: /Demo/ })).toBeVisible();
    await expectUsableOnAPhone(page);
  });
});

/**
 * The widths where an arrangement changes, which are the widths a discontinuity
 * can hide at.
 *
 * FR-011 asks that the layout be continuous: at every width from 360px up, a page
 * uses either the mobile or the desktop arrangement of each component, and there is
 * no width in between at which content is clipped or the body scrolls sideways.
 * Three widths cannot prove "every", but a discontinuity can only be introduced
 * where an arrangement switches, and the console has two such points. `sm` is where
 * the card list gives way to the table, so 640px is the first width at which a
 * table has to fit; `lg` is where the drawer stops being an overlay and becomes a
 * column, so 1023px is the last width at which it is laid over the page.
 */
const CONTINUITY_WIDTHS = [640, 1023] as const;

/**
 * The routes swept at those widths, chosen for what changes shape on them.
 *
 * The audit trail carries the console's widest table - five columns, one of them
 * structured detail - so 640px is the width at which it is most likely to push the
 * page out. The client list is the one whose card rendering the mobile sweep
 * asserts, so it is the one whose other direction is worth measuring at the width
 * where it takes over. The endpoint overview has no table at all: it is a detail
 * page with a tab strip and copyable issuer URLs, which is what keeps the drawer
 * measurement from being made only against lists.
 */
const CONTINUITY_ROUTES: readonly {
  readonly name: string;
  readonly url: string;
  readonly heading: string;
}[] = [
  {
    name: "the audit trail",
    url: `${SIGNET}/console/t/demo/audit`,
    heading: "Audit",
  },
  { name: "the client list", url: `${ENDPOINT}/clients`, heading: "Clients" },
  { name: "the endpoint overview", url: ENDPOINT, heading: "Integration" },
];

test.describe("console surfaces between the breakpoints", () => {
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  for (const route of CONTINUITY_ROUTES) {
    test(`fits ${route.name} at the widths where the layout changes`, async ({
      page,
    }) => {
      for (const width of CONTINUITY_WIDTHS) {
        await page.setViewportSize({ width, height: 780 });
        await page.goto(route.url);
        await expect(
          page.getByRole("heading", { name: route.heading }).first(),
        ).toBeVisible();
        await expectNoPageOverflow(page);

        // Below `lg` the drawer is still laid over the page rather than beside
        // it, so the overlay state has to be measured here too - 1023px is the
        // last width at which it exists at all.
        await openDrawer(page);
        await expectNoPageOverflow(page);
      }
    });
  }

  test("shows the client list as a table from sm upward", async ({ page }) => {
    // The other direction of FR-005's switch, measured at the width it happens
    // rather than at a desktop width where it proves less: 640px is `sm`, the
    // first width at which the table is what renders.
    await page.setViewportSize({ width: CONTINUITY_WIDTHS[0], height: 780 });
    await page.goto(`${ENDPOINT}/clients`);
    await expect(page.getByRole("heading", { name: "Clients" })).toBeVisible();

    await expect(page.locator("table")).toBeVisible();
    await expect(
      page.getByRole("listitem").filter({ hasText: "Stub SMART app" }),
    ).toBeHidden();
    await expectNoPageOverflow(page);
  });
});

test.describe("the console sign-in page", () => {
  // Rendered rather than submitted: this costs no sign-in from either limiter,
  // and what is under test is the layout of the form.
  test.use({ storageState: { cookies: [], origins: [] } });

  test("fits a phone", async ({ page }) => {
    await page.goto(`${SIGNET}/console`);
    await expect(page.getByLabel("Email")).toBeVisible();
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });
});

/** The policy editor: rules, builder, diff, version history and simulator. */
const POLICY = `${ENDPOINT}/policy`;

/** The EHR launch simulator. */
const LAUNCH = `${ENDPOINT}/launch`;

/**
 * One of the console's cards, found by the heading it carries.
 *
 * The policy page stacks nine of them on a phone, and almost every label on it -
 * "Add rule", "Simulate", "Values" - appears in more than one. Scoping to the card
 * is what keeps an assertion about the scope grants from passing because the claims
 * card happened to satisfy it.
 *
 * @param page - The page the card is on.
 * @param title - The card's heading, matched exactly.
 * @returns The card's `section`.
 */
function panelTitled(page: Page, title: string): Locator {
  return page
    .locator("section.card")
    .filter({ has: page.getByRole("heading", { name: title, exact: true }) });
}

/**
 * Fails when an element sticks out past the edge of the viewport.
 *
 * The complement of {@link expectNoPageOverflow}: a page can decline to scroll
 * sideways and still clip a code block, because an element wider than its parent
 * with the parent hiding the excess is exactly that. Read on the element itself, so
 * the failure names the container rather than the document.
 *
 * @param page - The page the element is on.
 * @param locator - The element to measure. Must resolve to exactly one node.
 * @throws {Error} When the element has no box, or when its box leaves the viewport.
 */
async function expectWithinViewport(
  page: Page,
  locator: Locator,
): Promise<void> {
  const width = page.viewportSize()?.width ?? 0;
  const box = await locator.boundingBox();
  expect(box, "the element has no box to measure").not.toBeNull();
  expect(
    box?.x ?? -1,
    "the element starts left of the viewport",
  ).toBeGreaterThanOrEqual(0);
  expect(
    (box?.x ?? 0) + (box?.width ?? 0),
    `the element reaches past ${String(width)}px`,
  ).toBeLessThanOrEqual(width);
}

/**
 * Fails unless wide content is held by its own container.
 *
 * Three facts together are what FR-002 asks for, and no two of them are enough. The
 * container fits the viewport; its content does not fit the container; and the
 * container really scrolls, rather than clipping what does not fit. A `pre` with
 * `overflow: hidden` satisfies the first two and loses half the token.
 *
 * @param page - The page the container is on.
 * @param locator - The scrolling container. Must resolve to exactly one node.
 * @throws {Error} When the container leaves the viewport, holds no overflow, or
 *   cannot be scrolled to reach it.
 * @example
 * ```ts
 * await expectScrollsInsideItself(page, panelTitled(page, "Simulate").locator("pre").first());
 * ```
 */
async function expectScrollsInsideItself(
  page: Page,
  locator: Locator,
): Promise<void> {
  await expectWithinViewport(page, locator);

  const extent = await extentOf(locator);
  expect(
    extent.scrollWidth,
    "the container holds no overflow, so this proves nothing",
  ).toBeGreaterThan(extent.clientWidth);

  const reached = await locator.evaluate((element: ScrollState) => {
    element.scrollLeft = element.scrollWidth;
    return element.scrollLeft;
  });
  expect(
    reached,
    "the container clips its content instead of scrolling",
  ).toBeGreaterThan(0);
}

/** How far an element is scrolled sideways, and how far it could be. */
interface ScrollState {
  scrollLeft: number;
  readonly scrollWidth: number;
}

test.describe("dense tools", () => {
  // The administrator session again: every one of these pages is admin-only, and
  // none of it costs an end-user sign-in.
  test.use({ storageState: CONSOLE_STORAGE_STATE });

  test("builds a rule of each kind in the policy editor at 360px", async ({
    page,
  }) => {
    await page.goto(POLICY);
    await expect(page.getByRole("heading", { name: "Policy" })).toBeVisible();
    await expectUsableOnAPhone(page);

    // Every list the builder offers, opened one at a time. A rule added here is
    // held in the editor's own state: nothing reaches the database until "Save and
    // publish", which this spec never presses, so the seeded policy the desktop
    // suite asserts against is left as it was.
    for (const list of [
      "Scope grants",
      "Claims",
      "Scope mappings",
      "Response parameters",
    ]) {
      const card = panelTitled(page, list);
      await card.getByRole("button", { name: "Add rule" }).click();
      await expectNoPageOverflow(page);
      await expectTapTargets(page, ENTRY_FIELDS);
    }

    // A grant rule is the richest of the four, and its pattern editor is the one
    // arrangement on the page that is a grid rather than a stack (FR-008: it may
    // collapse to one column, but nothing in it may go missing).
    const grants = panelTitled(page, "Scope grants");
    const added = grants.locator("ol > li").last();
    await expect(added.getByLabel("Context")).toBeVisible();
    await expect(added.getByLabel("Resource type")).toBeVisible();
    await expect(added.getByLabel("Decision")).toBeVisible();
    await expect(added.getByLabel("Narrow instead of refusing")).toBeVisible();
    await expect(added.getByLabel("Only for these grant types")).toBeVisible();
    // The five permission boxes, which are the reason the pattern is not a text
    // field: `.rs` and `.cruds` differ by a box.
    await expect(added.getByRole("checkbox")).toHaveCount(9);

    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });

  test("reorders and removes a policy rule at 360px", async ({ page }) => {
    await page.goto(POLICY);
    const grants = panelTitled(page, "Scope grants");
    const cards = grants.locator("ol > li");
    await expect(cards.first()).toBeVisible();
    const seeded = await cards.count();

    await grants.getByRole("button", { name: "Add rule" }).click();
    await expect(cards).toHaveCount(seeded + 1);

    // Order decides outcomes in this list, so moving a rule is a capability, not a
    // convenience: the new rule is last, and one press puts it second to last. The
    // expanded card following it is what says the move happened rather than a
    // rerender.
    await cards.last().getByRole("button", { name: "Move earlier" }).click();
    await expect(cards.nth(seeded - 1).getByLabel("Decision")).toBeVisible();

    await cards
      .nth(seeded - 1)
      .getByRole("button", { name: "Delete rule" })
      .click();
    await expect(cards).toHaveCount(seeded);
    await expectUsableOnAPhone(page);
  });

  test("edits a claim's value and its variables at 360px", async ({ page }) => {
    await page.goto(POLICY);
    const claims = panelTitled(page, "Claims");
    await claims.getByRole("button", { name: "Add rule" }).click();

    const added = claims.locator("ol > li").last();
    await added.getByLabel("Add a claim").fill("authorities");
    await added.getByRole("button", { name: "Add", exact: true }).click();

    // The value field and the variable inserter beside it: the smallest pair of
    // controls in the console, and the two a thumb is most likely to miss.
    await expect(added.getByLabel("Value for authorities")).toBeVisible();
    await added
      .getByLabel("Insert a variable into authorities")
      .selectOption("scope.resourceTypeSuffix");
    await expect(added.getByLabel("Value for authorities")).toHaveValue(
      "{{ scope.resourceTypeSuffix }}",
    );

    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });

  test("runs the token simulator and holds its output at 360px", async ({
    page,
  }) => {
    await page.goto(POLICY);
    const simulate = panelTitled(page, "Simulate");
    await simulate
      .getByLabel("Requested scopes")
      .fill("patient/Observation.rs");
    await simulate.getByLabel("Patient in context").fill("pat-9");
    await simulate.getByRole("button", { name: "Simulate" }).click();

    await expect(
      page.getByText("pathling:read:Observation").first(),
    ).toBeVisible({ timeout: 20_000 });

    // The decoded claims are the widest thing on the page: an issuer URL inside a
    // JSON string, in a `pre` that must not wrap. It scrolls; the page does not.
    await expectScrollsInsideItself(page, simulate.locator("pre").first());
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });

  test("shows the diff and the version history at 360px", async ({ page }) => {
    await page.goto(POLICY);
    const grants = panelTitled(page, "Scope grants");
    await grants.getByRole("button", { name: "Add rule" }).click();

    // An edit is what makes the save panel show a diff rather than "No changes
    // yet"; the diff is the thing being measured, so it has to exist first.
    const save = panelTitled(page, "Save");
    await expect(save.getByText("added,")).toBeVisible();
    await expectScrollsInsideItself(page, save.locator("pre"));

    // The history is a table on a desktop and a stack of cards here, and the
    // publish action stays with the version it belongs to (FR-006).
    const versions = panelTitled(page, "Versions");
    await expect(versions.locator("table")).toBeHidden();
    await expect(versions.getByRole("listitem").first()).toBeVisible();
    await expect(
      versions.getByRole("listitem").first().getByText("What changed"),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
  });

  test("offers the code view at 360px", async ({ page }) => {
    await page.goto(POLICY);
    await page.getByRole("tab", { name: "Code" }).click();

    // The document as text, editable rather than shown: the code view is a
    // capability, and FR-008 forbids dropping it on a phone.
    const editor = page.getByLabel("Policy document");
    await expect(editor).toBeEnabled();
    await expectWithinViewport(page, editor);
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);
  });

  test("mints a launch from the simulator at 360px", async ({ page }) => {
    await page.goto(LAUNCH);
    await expect(
      page.getByRole("heading", { name: "Launch simulator" }),
    ).toBeVisible();
    await expectUsableOnAPhone(page);
    await expectTapTargets(page, ENTRY_FIELDS);

    await page.getByLabel("Patient").fill("pat-9");
    await page.getByLabel("Intent").fill("reconcile-medications");
    await page.getByRole("button", { name: "Mint a launch" }).click();

    // The handle and the URL the EHR would open, both long single words with
    // nothing to break at, both copyable in full (FR-007). These wrap rather
    // than scroll - either is allowed, and wrapping is the better answer for a
    // value somebody is about to read back - so what is asserted is that the
    // whole of it is on screen rather than that it can be scrolled to.
    const minted = panelTitled(page, "Launch");
    await expect(minted.getByText("launch", { exact: true })).toBeVisible();
    await expect(
      minted.getByRole("button", { name: "Copy launch handle" }),
    ).toBeVisible();
    const url = minted.locator("code").last();
    await expect(url).toContainText("launch=");
    await expectWithinViewport(page, url);
    await expectUsableOnAPhone(page);
  });
});
