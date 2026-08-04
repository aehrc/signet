/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  canAdministerTenant,
  canWrite,
  roleAtLeast,
  TENANT_ROLES,
  wouldRemoveLastOwner,
} from "./roles.js";

import type { MembershipSummary, TenantRole } from "./roles.js";

/** Builds a membership list from `[adminUserId, role]` pairs. */
function members(
  entries: readonly [string, TenantRole][],
): readonly MembershipSummary[] {
  return entries.map(([adminUserId, role]) => ({ adminUserId, role }));
}

describe("TENANT_ROLES", () => {
  it("is ordered from least to most authority", () => {
    expect(TENANT_ROLES).toEqual(["viewer", "developer", "admin", "owner"]);
  });

  it("orders every role consistently with roleAtLeast", () => {
    for (const [heldIndex, held] of TENANT_ROLES.entries()) {
      for (const [requiredIndex, required] of TENANT_ROLES.entries()) {
        expect(roleAtLeast(held, required)).toBe(heldIndex >= requiredIndex);
      }
    }
  });
});

describe("roleAtLeast", () => {
  it("satisfies a requirement with the same role", () => {
    expect(roleAtLeast("developer", "developer")).toBe(true);
  });

  it("does not let a lesser role satisfy a greater requirement", () => {
    expect(roleAtLeast("developer", "admin")).toBe(false);
  });
});

describe("canAdministerTenant", () => {
  it("admits admins and owners only", () => {
    expect(canAdministerTenant("owner")).toBe(true);
    expect(canAdministerTenant("admin")).toBe(true);
    expect(canAdministerTenant("developer")).toBe(false);
    expect(canAdministerTenant("viewer")).toBe(false);
  });
});

describe("canWrite", () => {
  it("keeps a viewer read-only", () => {
    expect(canWrite("viewer")).toBe(false);
    expect(canWrite("developer")).toBe(true);
  });
});

describe("wouldRemoveLastOwner", () => {
  it("refuses removing the only owner", () => {
    expect(wouldRemoveLastOwner(members([["a", "owner"]]), "a", null)).toBe(
      true,
    );
  });

  it("refuses demoting the only owner", () => {
    expect(wouldRemoveLastOwner(members([["a", "owner"]]), "a", "admin")).toBe(
      true,
    );
  });

  it("permits removing an owner when another remains", () => {
    expect(
      wouldRemoveLastOwner(
        members([
          ["a", "owner"],
          ["b", "owner"],
        ]),
        "a",
        null,
      ),
    ).toBe(false);
  });

  it("permits removing a member who is not an owner", () => {
    expect(
      wouldRemoveLastOwner(
        members([
          ["a", "owner"],
          ["b", "admin"],
        ]),
        "b",
        null,
      ),
    ).toBe(false);
  });

  it("permits promoting somebody to owner", () => {
    expect(wouldRemoveLastOwner(members([["a", "owner"]]), "b", "owner")).toBe(
      false,
    );
  });

  it("permits re-asserting the only owner's own role", () => {
    expect(wouldRemoveLastOwner(members([["a", "owner"]]), "a", "owner")).toBe(
      false,
    );
  });

  it("permits adding a new member to an ownerless tenant it cannot make worse", () => {
    // No owner exists, so nothing is being removed; the caller is not the reason
    // the tenant is unadministrable and must not be blamed for it.
    expect(wouldRemoveLastOwner(members([["a", "admin"]]), "b", "viewer")).toBe(
      false,
    );
  });
});
