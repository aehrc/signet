/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  clientScopeFromRow,
  endpointScopeFromRow,
  tenantScopeFromRow,
  TenantScopeViolationError,
} from "./scope.js";

import type { Client } from "../schema/clients.js";
import type { Endpoint } from "../schema/endpoints.js";
import type { Tenant } from "../schema/tenancy.js";

const AT = new Date("2026-01-01T00:00:00.000Z");

const tenant: Tenant = {
  id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  slug: "demo",
  name: "Demo",
  createdAt: AT,
  updatedAt: AT,
};

/**
 * An endpoint row reduced to what the scope constructors read.
 *
 * Cast rather than fully populated: these tests are about ownership checks, and
 * spelling out thirty-five capability columns to assert one of them would bury the
 * assertion.
 */
function endpointRow(id: string, tenantId: string, slug = "e1"): Endpoint {
  return { id, tenantId, slug } as Endpoint;
}

/** A client row reduced to what the scope constructors read. */
function clientRow(id: string, endpointId: string, clientId = "app"): Client {
  return { id, endpointId, clientId } as Client;
}

describe("tenantScopeFromRow", () => {
  it("carries the tenant's identifier and slug", () => {
    const scope = tenantScopeFromRow(tenant);
    expect(scope.tenantId).toBe(tenant.id);
    expect(scope.tenantSlug).toBe("demo");
  });

  it("does not expose the brand as enumerable data", () => {
    // The brand is a symbol, so it survives neither JSON nor a spread of the
    // enumerable string keys - which is what makes a scope impossible to
    // reconstruct from a request body.
    const scope = tenantScopeFromRow(tenant);
    expect(Object.keys(scope)).toEqual(["tenantId", "tenantSlug"]);
    expect(JSON.stringify(scope)).toBe(
      `{"tenantId":"${tenant.id}","tenantSlug":"demo"}`,
    );
  });
});

describe("endpointScopeFromRow", () => {
  it("narrows a tenant scope to one of its endpoints", () => {
    const scope = endpointScopeFromRow(
      tenantScopeFromRow(tenant),
      endpointRow("e-1", tenant.id, "pathling"),
    );
    expect(scope.endpointId).toBe("e-1");
    expect(scope.endpointSlug).toBe("pathling");
    expect(scope.tenantId).toBe(tenant.id);
  });

  it("refuses an endpoint belonging to another tenant", () => {
    expect(() =>
      endpointScopeFromRow(
        tenantScopeFromRow(tenant),
        endpointRow("e-1", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
      ),
    ).toThrow(TenantScopeViolationError);
  });

  it("names both tenants in the error, so the mix-up is diagnosable", () => {
    expect(() =>
      endpointScopeFromRow(
        tenantScopeFromRow(tenant),
        endpointRow("e-1", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
      ),
    ).toThrow(/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/);
  });
});

describe("clientScopeFromRow", () => {
  const endpointScope = endpointScopeFromRow(
    tenantScopeFromRow(tenant),
    endpointRow("e-1", tenant.id),
  );

  it("carries both the surrogate key and the OAuth identifier", () => {
    const scope = clientScopeFromRow(
      endpointScope,
      clientRow("c-1", "e-1", "growth-chart"),
    );
    expect(scope.clientRowId).toBe("c-1");
    expect(scope.clientId).toBe("growth-chart");
  });

  it("remains usable wherever an endpoint or tenant scope is required", () => {
    const scope = clientScopeFromRow(endpointScope, clientRow("c-1", "e-1"));
    expect(scope.endpointId).toBe("e-1");
    expect(scope.tenantId).toBe(tenant.id);
  });

  it("refuses a client registered on another endpoint", () => {
    // The case that matters: client_id is globally unique, so a lookup without an
    // endpoint predicate can return a client from an entirely different tenant.
    expect(() =>
      clientScopeFromRow(endpointScope, clientRow("c-1", "e-2")),
    ).toThrow(TenantScopeViolationError);
  });
});
