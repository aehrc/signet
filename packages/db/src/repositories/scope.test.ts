/**
 * Author: John Grimes
 */

import { describe, expect, it } from "vitest";

import {
  clientScopeFromRow,
  declareTenantScope,
  endpointScopeFromRow,
  executorFor,
  isBoundScope,
  TENANT_SETTING,
  tenantScopeFromRow,
  TenantScopeViolationError,
} from "./scope.js";
import { createFakeExecutor } from "../test/fakeExecutor.js";

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

describe("declareTenantScope", () => {
  it("returns a scope carrying the tenant it declared", async () => {
    const fake = createFakeExecutor();
    const bound = await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    expect(bound.tenantId).toBe(tenant.id);
    expect(bound.tenantSlug).toBe("demo");
    // The transaction and the established tenant are now one value, which is
    // what makes it impossible to declare one tenant and query for another.
    expect(executorFor(bound)).toBe(fake.db);
  });

  it("declares the tenant with the value bound as a parameter", async () => {
    const fake = createFakeExecutor();
    await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    // Not interpolated: this is the one statement whose entire job is to enforce
    // a boundary, so the tenant must not reach it as SQL text.
    expect(fake.statements).toEqual([
      {
        text: "select set_config($1, $2, true)",
        params: [TENANT_SETTING, tenant.id],
      },
    ]);
  });

  it("asks for a transaction-local setting, so it cannot outlive the work", async () => {
    const fake = createFakeExecutor();
    await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    // The third argument to set_config is what releases the setting at the end of
    // the transaction, so the next request to borrow the pooled connection cannot
    // inherit this tenant.
    expect(fake.statements[0]?.text).toContain(", true)");
  });

  it("marks the scope as bound, which no hand-built object is", async () => {
    const fake = createFakeExecutor();
    const unbound = tenantScopeFromRow(tenant);

    expect(isBoundScope(unbound)).toBe(false);
    expect(isBoundScope(await declareTenantScope(fake.db, unbound))).toBe(true);

    // The brand is a module-private symbol holding the transaction itself, so a
    // bound scope cannot be assembled from data - only obtained by declaring.
    const forged = {
      ...unbound,
      tenantId: tenant.id,
      tenantSlug: "demo",
    } as unknown as Parameters<typeof isBoundScope>[0];
    expect(isBoundScope(forged)).toBe(false);
  });

  it("keeps the transaction out of the scope's enumerable data", async () => {
    const fake = createFakeExecutor();
    const bound = await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    // A symbol key, like the other brands: a bound scope still serialises to the
    // two fields it carries, and a transaction cannot end up in a response body.
    expect(Object.keys(bound)).toEqual(["tenantId", "tenantSlug"]);
    expect(JSON.stringify(bound)).toBe(
      `{"tenantId":"${tenant.id}","tenantSlug":"demo"}`,
    );
  });
});

describe("narrowing a bound scope", () => {
  it("preserves the binding through an endpoint and then a client", async () => {
    const fake = createFakeExecutor();
    const bound = await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    const endpointScope = endpointScopeFromRow(
      bound,
      endpointRow("e-1", tenant.id),
    );
    expect(isBoundScope(endpointScope)).toBe(true);
    expect(executorFor(endpointScope)).toBe(fake.db);

    const clientScope = clientScopeFromRow(
      endpointScope,
      clientRow("c-1", "e-1"),
    );
    expect(isBoundScope(clientScope)).toBe(true);
    expect(executorFor(clientScope)).toBe(fake.db);
    // Narrowing must not have declared anything a second time.
    expect(fake.statements).toHaveLength(1);
  });

  it("leaves an unbound scope unbound", () => {
    // Narrowing is not a way to acquire a binding: an endpoint scope narrowed
    // from a scope that declared nothing still has nothing declared.
    const endpointScope = endpointScopeFromRow(
      tenantScopeFromRow(tenant),
      endpointRow("e-1", tenant.id),
    );
    expect(isBoundScope(endpointScope)).toBe(false);
  });

  it("still refuses a row belonging to another tenant", async () => {
    const fake = createFakeExecutor();
    const bound = await declareTenantScope(fake.db, tenantScopeFromRow(tenant));

    // The binding does not replace the ownership check: a bound transaction is
    // proof of which tenant was declared, not proof that this row is theirs.
    expect(() =>
      endpointScopeFromRow(
        bound,
        endpointRow("e-1", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
      ),
    ).toThrow(TenantScopeViolationError);

    const endpointScope = endpointScopeFromRow(
      bound,
      endpointRow("e-1", tenant.id),
    );
    expect(() =>
      clientScopeFromRow(endpointScope, clientRow("c-1", "e-2")),
    ).toThrow(TenantScopeViolationError);
  });
});
