/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { invitationMailto } from "./invitationMailto.js";
import { formatInstant } from "../formatting/values.js";

const INVITATION = {
  to: "casey@example.org",
  endpointName: "Pathling & friends",
  username: "casey",
  url: "https://signet.example.org/t/demo/e/main/invitation#abc_DEF-123",
  expiresAt: "2026-11-20T03:00:00.000Z",
};

/** Splits a mailto link into its address and its decoded header fields. */
function parse(href: string): {
  readonly scheme: string;
  readonly to: string;
  readonly fields: URLSearchParams;
} {
  const [address = "", query = ""] = href.split("?");
  const [scheme = "", to = ""] = address.split(":");
  return {
    scheme,
    to: decodeURIComponent(to),
    fields: new URLSearchParams(query),
  };
}

describe("invitationMailto", () => {
  it("addresses the message to the address typed", () => {
    const { scheme, to } = parse(invitationMailto(INVITATION));
    expect(scheme).toBe("mailto");
    expect(to).toBe("casey@example.org");
  });

  it("leaves the @ readable, which some mail clients require", () => {
    expect(invitationMailto(INVITATION)).toStartWith(
      "mailto:casey@example.org?",
    );
  });

  it("ignores surrounding whitespace in the address", () => {
    const { to } = parse(
      invitationMailto({ ...INVITATION, to: "  casey@example.org " }),
    );
    expect(to).toBe("casey@example.org");
  });

  it("leaves the recipient empty when no address was typed", () => {
    expect(invitationMailto({ ...INVITATION, to: "" })).toStartWith(
      "mailto:?subject=",
    );
  });

  it("names the endpoint in the subject", () => {
    const { fields } = parse(invitationMailto(INVITATION));
    expect(fields.get("subject")).toBe("Your account on Pathling & friends");
  });

  it("puts the link, the username, the endpoint and the expiry in the body", () => {
    const body = parse(invitationMailto(INVITATION)).fields.get("body") ?? "";
    expect(body).toContain(INVITATION.url);
    expect(body).toContain("casey");
    expect(body).toContain("Pathling & friends");
    expect(body).toContain(formatInstant(INVITATION.expiresAt));
  });

  it("keeps the link intact rather than letting its fragment end the URI", () => {
    const href = invitationMailto(INVITATION);
    // A raw `#` would end the mailto URI there, and the body would lose the token.
    expect(href).not.toContain("#");
    expect(href).not.toContain(" ");
  });

  it("breaks lines the way RFC 6068 asks", () => {
    expect(invitationMailto(INVITATION)).toContain("%0D%0A");
  });

  it("encodes an address that would otherwise start a header field", () => {
    const { to, fields } = parse(
      invitationMailto({ ...INVITATION, to: "a@b.org?cc=c@d.org" }),
    );
    expect(to).toBe("a@b.org?cc=c@d.org");
    expect(fields.get("cc")).toBeNull();
  });
});
