/**
 * Author: John Grimes
 */

import { describe, expect, test } from "bun:test";

import { resolveStackUrls } from "./stackUrls.js";

describe("resolveStackUrls", () => {
  // With nothing set, the suite must address the ports the compose file
  // publishes by default. These are the values the whole suite was written
  // against, so a change here breaks every spec.
  test("defaults to the ports the compose file publishes", () => {
    expect(resolveStackUrls({})).toEqual({
      signet: "http://localhost:3000",
      fhir: "http://localhost:8080/fhir",
      app: "http://localhost:4000",
    });
  });

  // The bug this exists for: the suite honoured SIGNET_PORT and ignored the
  // other two, so moving the stack meant setting five variables rather than
  // three.
  test("moves every service when the three port variables are set", () => {
    expect(
      resolveStackUrls({
        SIGNET_PORT: "3100",
        PATHLING_PORT: "8180",
        APP_PORT: "4100",
      }),
    ).toEqual({
      signet: "http://localhost:3100",
      fhir: "http://localhost:8180/fhir",
      app: "http://localhost:4100",
    });
  });

  // Each port moves its own service and nothing else, so a machine with one
  // port taken sets one variable.
  test("moves one service without disturbing the others", () => {
    expect(resolveStackUrls({ PATHLING_PORT: "8180" })).toEqual({
      signet: "http://localhost:3000",
      fhir: "http://localhost:8180/fhir",
      app: "http://localhost:4000",
    });
  });

  // A stack somewhere other than localhost - a remote host, a different scheme,
  // a path prefix - is addressed by base URL, and the port variable cannot
  // express it. So the base URL wins outright rather than being combined.
  test("prefers an explicit base URL over the port it would derive", () => {
    expect(
      resolveStackUrls({
        SIGNET_PORT: "3100",
        PATHLING_PORT: "8180",
        APP_PORT: "4100",
        SIGNET_BASE_URL: "https://signet.example.org",
        PATHLING_BASE_URL: "https://fhir.example.org/fhir",
        APP_BASE_URL: "https://app.example.org",
      }),
    ).toEqual({
      signet: "https://signet.example.org",
      fhir: "https://fhir.example.org/fhir",
      app: "https://app.example.org",
    });
  });

  // One base URL set and the other two unset: the two fall back to their ports
  // rather than to the origin of the one that was set.
  test("falls back per service when only one base URL is set", () => {
    expect(
      resolveStackUrls({
        SIGNET_BASE_URL: "https://signet.example.org",
        PATHLING_PORT: "8180",
      }),
    ).toEqual({
      signet: "https://signet.example.org",
      fhir: "http://localhost:8180/fhir",
      app: "http://localhost:4000",
    });
  });

  // An empty string is what an exported-but-cleared variable looks like, and
  // reading it as a port would produce `http://localhost:/fhir`.
  test("treats an empty variable as unset", () => {
    expect(
      resolveStackUrls({
        SIGNET_PORT: "",
        PATHLING_BASE_URL: "",
        APP_PORT: "",
      }),
    ).toEqual({
      signet: "http://localhost:3000",
      fhir: "http://localhost:8080/fhir",
      app: "http://localhost:4000",
    });
  });
});
