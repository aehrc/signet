/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";
import path from "node:path";

import {
  cacheControlFor,
  contentTypeFor,
  isReservedPath,
  resolveWithinRoot,
  wantsApplicationShell,
} from "./staticFiles.js";

const root = path.resolve("/srv/signet/web");

describe("isReservedPath", () => {
  it("reserves the admin API", () => {
    expect(isReservedPath("/api/v1/session")).toBe(true);
    expect(isReservedPath("/api")).toBe(true);
  });

  it("reserves the endpoint issuers", () => {
    expect(isReservedPath("/t/demo/e/fhir/token")).toBe(true);
  });

  it("reserves the probes", () => {
    expect(isReservedPath("/healthz")).toBe(true);
    expect(isReservedPath("/readyz")).toBe(true);
  });

  it("does not reserve a console route", () => {
    expect(isReservedPath("/console/endpoints")).toBe(false);
  });

  it("does not reserve a path that merely begins with a reserved word", () => {
    // `/tenants` is a UI route; only `/t/` is the issuer prefix.
    expect(isReservedPath("/tenants")).toBe(false);
  });

  it("does not reserve the end-user pages under an issuer", () => {
    // These five are part of the UI and are served from the bundle, even though
    // everything else under the issuer prefix is an OAuth endpoint.
    for (const page of ["login", "picker", "consent", "manage", "apps"]) {
      expect(isReservedPath(`/t/demo/e/fhir/${page}`)).toBe(false);
    }
  });

  it("still reserves the API those pages call", () => {
    expect(isReservedPath("/t/demo/e/fhir/manage/session")).toBe(true);
    expect(isReservedPath("/t/demo/e/fhir/apps/requests")).toBe(true);
  });
});

describe("resolveWithinRoot", () => {
  it("resolves an ordinary asset", () => {
    expect(resolveWithinRoot(root, "/assets/index.js")).toBe(
      path.resolve(root, "assets/index.js"),
    );
  });

  it("neutralises a traversal instead of escaping the root", () => {
    // An absolute path cannot rise above its own root, so normalisation collapses
    // the `..` segments and the result addresses a file inside the web root that
    // does not exist. The important property is that it is inside.
    expect(resolveWithinRoot(root, "/../../etc/passwd")).toBe(
      path.resolve(root, "etc/passwd"),
    );
  });

  it("neutralises an encoded traversal identically", () => {
    // Decoding happens before normalisation, so `..%2f` and `../` take the same
    // path through this function - which is why the containment check is applied
    // to the resolved value rather than to the requested one.
    expect(resolveWithinRoot(root, "/..%2f..%2fetc%2fpasswd")).toBe(
      path.resolve(root, "etc/passwd"),
    );
  });

  it("refuses anything that still resolves outside the root", () => {
    // A request path always begins with a slash, which is what makes the cases
    // above collapse. The containment check does not depend on that: given a
    // relative path that does escape, it refuses rather than serving.
    expect(resolveWithinRoot(root, "../web-old/secret")).toBeUndefined();
  });

  it("refuses a malformed percent-encoding", () => {
    expect(resolveWithinRoot(root, "/%zz")).toBeUndefined();
  });

  it("refuses a path containing a NUL byte", () => {
    expect(resolveWithinRoot(root, "/index.html%00.js")).toBeUndefined();
  });

  it("does not accept a sibling directory whose name shares the prefix", () => {
    // `/srv/web-old` starts with `/srv/web`, so a prefix comparison without the
    // separator would let it through.
    expect(
      resolveWithinRoot(path.resolve("/srv/web"), "../web-old/secret"),
    ).toBeUndefined();
  });
});

describe("contentTypeFor", () => {
  it("names the types a build emits", () => {
    expect(contentTypeFor("/w/index.html")).toContain("text/html");
    expect(contentTypeFor("/w/app.js")).toContain("text/javascript");
    expect(contentTypeFor("/w/app.css")).toContain("text/css");
    expect(contentTypeFor("/w/logo.svg")).toBe("image/svg+xml");
  });

  it("does not guess at an unknown extension", () => {
    expect(contentTypeFor("/w/thing.weird")).toBe("application/octet-stream");
  });

  it("is case-insensitive about the extension", () => {
    expect(contentTypeFor("/w/LOGO.PNG")).toBe("image/png");
  });
});

describe("cacheControlFor", () => {
  it("caches fingerprinted assets for a year", () => {
    expect(cacheControlFor("/assets/index-abc123.js")).toContain("immutable");
  });

  it("never caches the document that names them", () => {
    expect(cacheControlFor("/")).toBe("no-cache");
    expect(cacheControlFor("/console/endpoints")).toBe("no-cache");
  });
});

describe("wantsApplicationShell", () => {
  it("serves the shell to a navigation", () => {
    expect(
      wantsApplicationShell("GET", "text/html,application/xhtml+xml"),
    ).toBe(true);
  });

  it("does not serve it to a script's fetch", () => {
    expect(wantsApplicationShell("GET", "application/json")).toBe(false);
    expect(wantsApplicationShell("GET", undefined)).toBe(false);
  });

  it("does not serve it in response to a write", () => {
    expect(wantsApplicationShell("POST", "text/html")).toBe(false);
  });
});
