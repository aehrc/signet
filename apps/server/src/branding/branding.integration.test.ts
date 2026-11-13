/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A tenant's logo, from upload in the admin API to the public routes the end-user
 * pages read it from.
 *
 * Author: John Grimes
 */

import { MAX_LOGO_BYTES } from "@signet/core";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "bun:test";

import { adminJson, credentialHeaders, tenantPath } from "../test/adminApi.js";
import { createTestStack, testDatabaseUrl } from "../test/harness.js";

import type { AdminCredential } from "../test/adminApi.js";
import type { TestStack } from "../test/harness.js";
import type { TenantBranding } from "@signet/core";

const PNG_SIGNATURE = Uint8Array.of(
  0x89,
  0x50,
  0x4e,
  0x47,
  0x0d,
  0x0a,
  0x1a,
  0x0a,
);

/** Bytes that begin like a PNG; the server inspects signatures, not pixels. */
function png(length = 64, fill = 0): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length).fill(fill);
  bytes.set(PNG_SIGNATURE);
  return bytes;
}

const SVG = new TextEncoder().encode(
  '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
);

/** What the public branding route answers. */
interface BrandingResponse {
  readonly branding: TenantBranding | null;
}

describe.skipIf(testDatabaseUrl === undefined)("tenant logos", () => {
  let stack: TestStack;
  let owner: AdminCredential;

  /** Uploads raw bytes as one of the tenant's logos. */
  async function upload(
    variant: string,
    body: Uint8Array<ArrayBuffer>,
    options: {
      readonly credential?: AdminCredential;
      readonly contentType?: string;
    } = {},
  ): Promise<Response> {
    return await stack.app.request(tenantPath(stack, `/logo/${variant}`), {
      method: "PUT",
      headers: {
        ...credentialHeaders(options.credential ?? owner),
        "content-type": options.contentType ?? "application/octet-stream",
      },
      body,
    });
  }

  /** Removes one of the tenant's logos. */
  async function remove(
    variant: string,
    credential: AdminCredential = owner,
  ): Promise<Response> {
    return await stack.app.request(tenantPath(stack, `/logo/${variant}`), {
      method: "DELETE",
      headers: credentialHeaders(credential),
    });
  }

  /** Reads the public branding view, as an end-user page does. */
  async function branding(): Promise<TenantBranding | null> {
    const response = await stack.app.request(
      `/t/${stack.tenant.slug}/branding`,
    );
    expect(response.status).toBe(200);
    return ((await response.json()) as BrandingResponse).branding;
  }

  beforeAll(async () => {
    stack = await createTestStack();
    owner = { cookie: await stack.signIn() };
  });

  afterAll(async () => {
    await stack.close();
  });

  beforeEach(async () => {
    // Every test starts from a tenant with no logo.
    await remove("light");
  });

  describe("the branding view", () => {
    it("is null for a tenant with no logo, so the pages keep the Signet wordmark", async () => {
      expect(await branding()).toBeNull();
    });

    it("names the tenant and points at a versioned logo once one is uploaded", async () => {
      const response = await upload("light", png());
      expect(response.status).toBe(200);

      const view = await branding();
      expect(view?.name).toBe(stack.tenant.name);
      expect(view?.logoUrl).toMatch(
        new RegExp(String.raw`^/t/${stack.tenant.slug}/logo/light\?v=\d+$`),
      );
      expect(view?.darkLogoUrl).toBeNull();
    });

    it("offers the dark variant beside the logo", async () => {
      await upload("light", png());
      expect((await upload("dark", png(64, 1))).status).toBe(200);

      expect((await branding())?.darkLogoUrl).toMatch(
        new RegExp(String.raw`^/t/${stack.tenant.slug}/logo/dark\?v=\d+$`),
      );
    });

    it("changes the logo's URL when the logo is replaced", async () => {
      await upload("light", png());
      const before = (await branding())?.logoUrl;
      stack.setNow(new Date(Date.now() + 60_000));
      await upload("light", png(64, 2));
      const after = (await branding())?.logoUrl;

      // The URL is what a browser caches by, so a replacement must not share it.
      expect(after).toBeDefined();
      expect(after).not.toBe(before);
    });

    it("answers 404 for a tenant that does not exist", async () => {
      const response = await stack.app.request("/t/no-such-tenant/branding");
      expect(response.status).toBe(404);
    });
  });

  describe("serving a logo", () => {
    it("serves the stored bytes as the type they were sniffed as, not the type claimed", async () => {
      const bytes = png();
      await upload("light", bytes, { contentType: "text/html" });

      const response = await stack.app.request(
        `/t/${stack.tenant.slug}/logo/light`,
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toBe("image/png");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect([...new Uint8Array(await response.arrayBuffer())]).toEqual([
        ...bytes,
      ]);
    });

    it("sandboxes an SVG so that a script inside it cannot run on this origin", async () => {
      expect((await upload("light", SVG)).status).toBe(200);

      const response = await stack.app.request(
        `/t/${stack.tenant.slug}/logo/light`,
      );
      expect(response.headers.get("content-type")).toBe("image/svg+xml");
      const policy = response.headers.get("content-security-policy") ?? "";
      expect(policy).toContain("sandbox");
      expect(policy).toContain("default-src 'none'");
    });

    it("lets a browser cache the versioned URL indefinitely, and only that URL", async () => {
      await upload("light", png());
      const versioned = (await branding())?.logoUrl ?? "";

      const current = await stack.app.request(versioned);
      expect(current.headers.get("cache-control")).toContain("immutable");

      // A stale or missing version must be revalidated, or a browser holding it
      // would keep showing a logo that has since been replaced.
      const unversioned = await stack.app.request(
        `/t/${stack.tenant.slug}/logo/light`,
      );
      expect(unversioned.headers.get("cache-control")).toBe("no-cache");
      const stale = await stack.app.request(
        `/t/${stack.tenant.slug}/logo/light?v=1`,
      );
      expect(stale.headers.get("cache-control")).toBe("no-cache");
    });

    it("answers 404 for a variant the tenant does not hold, or that does not exist", async () => {
      await upload("light", png());
      for (const variant of ["dark", "sepia"]) {
        const response = await stack.app.request(
          `/t/${stack.tenant.slug}/logo/${variant}`,
        );
        expect(response.status).toBe(404);
      }
    });

    it("answers 404 for a tenant with no logo", async () => {
      const response = await stack.app.request(
        `/t/${stack.tenant.slug}/logo/light`,
      );
      expect(response.status).toBe(404);
    });
  });

  describe("uploading", () => {
    it("accepts a logo of exactly the maximum size", async () => {
      expect((await upload("light", png(MAX_LOGO_BYTES))).status).toBe(200);
    });

    it("refuses a logo over the maximum size", async () => {
      expect((await upload("light", png(MAX_LOGO_BYTES + 1))).status).toBe(413);
      expect(await branding()).toBeNull();
    });

    it("refuses a file that is not an accepted image, and says what is accepted", async () => {
      const response = await upload(
        "light",
        new TextEncoder().encode("<html><body>hello</body></html>"),
        { contentType: "image/png" },
      );
      expect(response.status).toBe(400);
      const body = (await response.json()) as { message: string };
      expect(body.message).toContain("PNG, JPEG, WebP or SVG");
      expect(await branding()).toBeNull();
    });

    it("refuses an empty upload", async () => {
      expect((await upload("light", new Uint8Array(0))).status).toBe(400);
    });

    it("refuses a dark variant before there is a logo for it to replace", async () => {
      const response = await upload("dark", png());
      expect(response.status).toBe(409);
      expect(await branding()).toBeNull();
    });

    it("answers 404 for a variant that does not exist", async () => {
      expect((await upload("sepia", png())).status).toBe(404);
    });

    it("returns the branding view the upload produced", async () => {
      const response = await upload("light", png());
      const body = (await response.json()) as BrandingResponse;
      expect(body.branding?.name).toBe(stack.tenant.name);
      expect(body.branding?.logoUrl).toBe((await branding())?.logoUrl ?? "");
    });

    it("records the upload and the removal in the audit trail", async () => {
      await upload("light", png());
      await remove("light");

      for (const action of ["tenant-logo.updated", "tenant-logo.removed"]) {
        const audit = await adminJson<{
          events: { action: string; detail: Record<string, unknown> }[];
        }>(stack, "GET", tenantPath(stack, `/audit?action=${action}`), {
          credential: owner,
        });
        expect(audit.events[0]?.detail["variant"]).toBe("light");
      }
    });

    it("refuses a developer, who may not change tenant settings", async () => {
      const developer = { bearer: await stack.mintApiToken("developer") };
      expect(
        (await upload("light", png(), { credential: developer })).status,
      ).toBe(403);
      await upload("light", png());
      expect((await remove("light", developer)).status).toBe(403);
    });

    it("refuses a caller who is not signed in", async () => {
      const response = await stack.app.request(
        tenantPath(stack, "/logo/light"),
        {
          method: "PUT",
          body: png(),
        },
      );
      expect(response.status).toBe(401);
    });
  });

  describe("removing", () => {
    it("removes the dark variant with the logo, and the pages fall back to Signet", async () => {
      await upload("light", png());
      await upload("dark", png(64, 1));

      expect((await remove("light")).status).toBe(200);
      expect(await branding()).toBeNull();
      const dark = await stack.app.request(`/t/${stack.tenant.slug}/logo/dark`);
      expect(dark.status).toBe(404);
    });

    it("removes only the dark variant when asked to", async () => {
      await upload("light", png());
      await upload("dark", png(64, 1));

      expect((await remove("dark")).status).toBe(200);
      const view = await branding();
      expect(view?.logoUrl).toBeDefined();
      expect(view?.darkLogoUrl).toBeNull();
    });

    it("answers 404 when there is nothing to remove", async () => {
      expect((await remove("light")).status).toBe(404);
    });
  });
});
