import { describe, expect, it } from "vitest";

import { roleAllows } from "./useConsole.js";

describe("roleAllows", () => {
  it("permits the exact role", () => {
    expect(roleAllows("admin", "admin")).toBe(true);
  });

  it("permits a higher role", () => {
    // The case an equality check gets wrong, and the reason this is a comparison.
    expect(roleAllows("owner", "admin")).toBe(true);
    expect(roleAllows("developer", "viewer")).toBe(true);
  });

  it("refuses a lower role", () => {
    expect(roleAllows("viewer", "developer")).toBe(false);
    expect(roleAllows("admin", "owner")).toBe(false);
  });

  it("refuses a role it does not recognise", () => {
    expect(roleAllows("something-new", "viewer")).toBe(false);
  });

  it("refuses when the requirement is not a role it recognises", () => {
    // Fails closed: an unknown requirement hides the control rather than showing
    // it to everybody.
    expect(roleAllows("owner", "superuser")).toBe(false);
  });
});
