/**
 * Author: John Grimes
 */

import { describe, expect, it } from "bun:test";

import { clientFormValues, clientPatch } from "./clientEdit.js";

import type { ClientView } from "../api/types.js";

/** A client as the API returns it, with the fields a case cares about overridden. */
function clientView(overrides: Partial<ClientView> = {}): ClientView {
  return {
    clientId: "client-1",
    name: "Growth Charts",
    description: null,
    logoUrl: null,
    clientType: "public",
    hasSecret: false,
    secretExpiresAt: null,
    jwks: null,
    jwksUri: null,
    redirectUris: ["https://app.example.com/cb"],
    launchUri: null,
    grantTypes: ["authorization_code"],
    allowedScopes: ["patient/Observation.rs", "launch/patient"],
    status: "active",
    contactEmail: null,
    createdAt: "2026-08-03T14:02:11.000Z",
    ...overrides,
  };
}

describe("clientFormValues", () => {
  it("renders the lists one value per line", () => {
    // The form edits both as text, and the parser round-trips this exact shape.
    expect(
      clientFormValues(
        clientView({
          redirectUris: [
            "https://a.example.com/cb",
            "https://b.example.com/cb",
          ],
        }),
      ),
    ).toEqual({
      name: "Growth Charts",
      status: "active",
      redirectUris: "https://a.example.com/cb\nhttps://b.example.com/cb",
      allowedScopes: "patient/Observation.rs\nlaunch/patient",
    });
  });

  it("renders empty lists as empty fields", () => {
    const values = clientFormValues(
      clientView({ redirectUris: [], allowedScopes: [] }),
    );

    expect(values.redirectUris).toBe("");
    expect(values.allowedScopes).toBe("");
  });
});

describe("clientPatch", () => {
  it("is empty for a form nobody touched", () => {
    // The point of the whole exercise: an untouched form must produce nothing to
    // send, because the API accepts an empty patch and writes a `client.updated`
    // audit event naming no fields, which nobody asked for and nobody can undo.
    const current = clientView();

    expect(clientPatch(clientFormValues(current), current)).toEqual({});
  });

  it("is empty when an edit is undone", () => {
    // Typing and retyping the same value is not a change, so the state has to be
    // about what the form holds rather than about it having been interacted with.
    const current = clientView();
    const values = clientFormValues(current);

    expect(clientPatch({ ...values, name: "Something" }, current)).not.toEqual(
      {},
    );
    expect(clientPatch({ ...values, name: "Growth Charts" }, current)).toEqual(
      {},
    );
  });

  it("carries only the field that changed", () => {
    const current = clientView();

    expect(
      clientPatch(
        { ...clientFormValues(current), name: "Growth Charts v2" },
        current,
      ),
    ).toEqual({ name: "Growth Charts v2" });
  });

  it("carries a changed status on its own", () => {
    const current = clientView();

    expect(
      clientPatch(
        { ...clientFormValues(current), status: "suspended" },
        current,
      ),
    ).toEqual({ status: "suspended" });
  });

  it("parses the redirect URIs into an array", () => {
    const current = clientView();

    expect(
      clientPatch(
        {
          ...clientFormValues(current),
          redirectUris:
            "https://one.example.com/cb\nhttps://two.example.com/cb",
        },
        current,
      ),
    ).toEqual({
      redirectUris: [
        "https://one.example.com/cb",
        "https://two.example.com/cb",
      ],
    });
  });

  it("treats reordered lists as a change", () => {
    // Order is significant for redirect URIs, so a reorder is an edit even though
    // the two lists hold the same values.
    const current = clientView({
      redirectUris: ["https://a.example.com/cb", "https://b.example.com/cb"],
    });

    expect(
      clientPatch(
        {
          ...clientFormValues(current),
          redirectUris: "https://b.example.com/cb\nhttps://a.example.com/cb",
        },
        current,
      ),
    ).toEqual({
      redirectUris: ["https://b.example.com/cb", "https://a.example.com/cb"],
    });
  });

  it("ignores trailing whitespace in a list field", () => {
    // A textarea gains a trailing newline the moment somebody puts the cursor at
    // the end of it, and that is not an edit.
    const current = clientView();
    const values = clientFormValues(current);

    expect(
      clientPatch(
        { ...values, redirectUris: `${values.redirectUris}\n  ` },
        current,
      ),
    ).toEqual({});
  });

  it("splits scopes on whitespace rather than on commas", () => {
    // A SMART scope can carry a comma inside its search parameters, so splitting
    // on one would corrupt it.
    const current = clientView();

    expect(
      clientPatch(
        {
          ...clientFormValues(current),
          allowedScopes: "patient/Observation.rs?category=a,b",
        },
        current,
      ),
    ).toEqual({ allowedScopes: ["patient/Observation.rs?category=a,b"] });
  });

  it("sends an emptied list as an empty array", () => {
    // Clearing every redirect URI is a deliberate instruction, distinct from not
    // touching the field, so it has to reach the API as an empty list.
    const current = clientView();

    expect(
      clientPatch({ ...clientFormValues(current), redirectUris: "" }, current),
    ).toEqual({ redirectUris: [] });
  });

  it("carries every changed field together", () => {
    const current = clientView();

    expect(
      clientPatch(
        {
          name: "Renamed",
          status: "suspended",
          redirectUris: "https://new.example.com/cb",
          allowedScopes: "openid fhirUser",
        },
        current,
      ),
    ).toEqual({
      name: "Renamed",
      status: "suspended",
      redirectUris: ["https://new.example.com/cb"],
      allowedScopes: ["openid", "fhirUser"],
    });
  });
});
