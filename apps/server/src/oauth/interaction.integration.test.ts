/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The interaction API against a real database.
 *
 * The property under test is the one the module header claims: a caller cannot skip a
 * step, and cannot influence what was recorded at `/authorize`. Each negative case
 * here is an attempt to do one of those.
 *
 * Author: John Grimes
 */

import {
  getAuthorizationSession,
  listConsentsForEndUser,
  withTenantScope,
} from "@signet/db";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import {
  decideConsent,
  interactionState,
  issuerPath,
  login,
  pkcePair,
  selectContext,
  startAuthorization,
} from "../test/flows.js";
import {
  createTestStack,
  TEST_PASSWORD,
  testDatabaseUrl,
} from "../test/harness.js";

import type { TestStack } from "../test/harness.js";

const describeWithDatabase =
  testDatabaseUrl === undefined ? describe.skip : describe;

/** The scopes that need a patient in context, so the picker is exercised. */
const PATIENT_SCOPES = "openid fhirUser launch/patient patient/Observation.rs";

describeWithDatabase("the interaction API", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack();
  });

  afterAll(async () => {
    await stack.close();
  });

  /** Starts an authorization needing login, a patient and consent. */
  async function newSession(scope = PATIENT_SCOPES): Promise<string> {
    return await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope,
      challenge: (await pkcePair()).challenge,
    });
  }

  it("reports what the consent screen has to show", async () => {
    const session = await newSession();
    const state = await interactionState(stack, session);

    expect(state.step).toBe("login");
    expect(state.requestedScopes).toEqual([
      "openid",
      "fhirUser",
      "launch/patient",
      "patient/Observation.rs",
    ]);
    // The endpoint is non-production, so the seeded persona is offered.
    expect(state.personas.map((persona) => persona.id)).toContain(
      stack.persona.id,
    );
  });

  it("walks login, then context, then consent, in that order", async () => {
    const session = await newSession();

    const afterLogin = (await (
      await login(stack, session, {
        username: "clinician",
        password: TEST_PASSWORD,
      })
    ).json()) as { step: string; patients: string[] };
    expect(afterLogin.step).toBe("select-context");
    // The clinician's configured patient list, from `attributes.patients`.
    expect(afterLogin.patients).toEqual(["pat-1", "pat-2"]);

    const afterContext = (await (
      await selectContext(stack, session, { patient: "pat-2" })
    ).json()) as { step: string };
    expect(afterContext.step).toBe("consent");

    const afterConsent = (await (
      await decideConsent(stack, session, true)
    ).json()) as { step: string; redirectTo: string };
    expect(afterConsent.step).toBe("complete");
    expect(
      new URL(afterConsent.redirectTo).searchParams.get("code"),
    ).not.toBeNull();
  });

  it("refuses to consent before anybody has signed in", async () => {
    const session = await newSession();
    const response = (await (
      await decideConsent(stack, session, true)
    ).json()) as { step: string };

    // Answered with the step that is actually outstanding, and nothing consented.
    expect(response.step).toBe("login");
    const row = await withTenantScope(stack.context.db, stack.scope, (bound) =>
      getAuthorizationSession(bound, session),
    );
    expect(row?.consentGrantedAt).toBeNull();
  });

  it("refuses to select a context before anybody has signed in", async () => {
    const session = await newSession();
    const response = (await (
      await selectContext(stack, session, { patient: "pat-1" })
    ).json()) as { step: string };
    expect(response.step).toBe("login");

    const row = await withTenantScope(stack.context.db, stack.scope, (bound) =>
      getAuthorizationSession(bound, session),
    );
    expect(row?.resolvedContext).toBeNull();
  });

  it("resolves a persona's default patient without asking", async () => {
    const session = await newSession();
    const state = (await (
      await login(stack, session, { personaId: stack.persona.id })
    ).json()) as { step: string };

    // The persona has exactly one candidate patient, so there is nothing to pick.
    expect(state.step).toBe("consent");
    const row = await withTenantScope(stack.context.db, stack.scope, (bound) =>
      getAuthorizationSession(bound, session),
    );
    expect(row?.resolvedContext).toMatchObject({ patient: "pat-9" });
  });

  it("refuses a wrong password, and says nothing about which part was wrong", async () => {
    const session = await newSession();
    const wrongPassword = await login(stack, session, {
      username: "clinician",
      password: "not the password",
    });
    const unknownUser = await login(stack, session, {
      username: "nobody",
      password: TEST_PASSWORD,
    });

    expect(wrongPassword.status).toBe(401);
    expect(unknownUser.status).toBe(401);
    await expect(wrongPassword.json()).resolves.toEqual(
      await unknownUser.json(),
    );
  });

  it("refuses a persona that is not a persona", async () => {
    const session = await newSession();
    const response = await login(stack, session, {
      personaId: stack.user.id,
    });
    expect(response.status).toBe(401);
  });

  it("refuses a patient the user may not act on", async () => {
    const session = await newSession();
    await login(stack, session, {
      username: "clinician",
      password: TEST_PASSWORD,
    });

    // The harness endpoint is non-production, which permits an identifier outside the
    // user's list - but not one that is not a FHIR id at all.
    const malformed = await selectContext(stack, session, {
      patient: "not a patient id",
    });
    expect(malformed.status).toBe(400);
  });

  it("delivers a refusal to the app as access_denied and abandons the session", async () => {
    const session = await newSession();
    await login(stack, session, {
      username: "clinician",
      password: TEST_PASSWORD,
    });
    await selectContext(stack, session, { patient: "pat-1" });

    const declined = (await (
      await decideConsent(stack, session, false)
    ).json()) as { step: string; redirectTo: string };

    expect(declined.step).toBe("denied");
    const url = new URL(declined.redirectTo);
    expect(url.searchParams.get("error")).toBe("access_denied");
    expect(
      await withTenantScope(stack.context.db, stack.scope, (bound) =>
        getAuthorizationSession(bound, session),
      ),
    ).toBeUndefined();
  });

  it("answers 404 for a session that does not exist", async () => {
    const response = await stack.app.request(
      `${issuerPath(stack)}/interaction/00000000-0000-0000-0000-000000000000`,
    );
    expect(response.status).toBe(404);
  });

  it("does not store a consent in `always` mode", async () => {
    const session = await newSession();
    await login(stack, session, {
      username: "clinician",
      password: TEST_PASSWORD,
    });
    await selectContext(stack, session, { patient: "pat-1" });
    await decideConsent(stack, session, true);

    // A stored consent in `always` mode would show the user a standing permission on
    // the management page that the server never actually honours.
    const consents = await withTenantScope(
      stack.context.db,
      stack.scope,
      (bound) => listConsentsForEndUser(bound, stack.user.id),
    );
    expect(consents).toHaveLength(0);
  });
});

describeWithDatabase("an endpoint that remembers consent", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      endpoint: {
        slug: "fhir",
        name: "Remembering",
        fhirBaseUrl: "https://fhir.test/R4",
        isProduction: false,
        consentMode: "remember",
      },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("prompts once and then skips the prompt", async () => {
    /** Runs an authorization and reports the step reached after signing in. */
    const stepAfterLogin = async (): Promise<string> => {
      const session = await startAuthorization(stack, {
        clientId: stack.publicClient.clientId,
        scope: "openid fhirUser",
        challenge: (await pkcePair()).challenge,
      });
      const state = (await (
        await login(stack, session, {
          username: "clinician",
          password: TEST_PASSWORD,
        })
      ).json()) as { step: string };
      if (state.step === "consent") {
        await decideConsent(stack, session, true);
      }
      return state.step;
    };

    expect(await stepAfterLogin()).toBe("consent");
    // The stored consent covers the same scopes, so the second run goes straight
    // through.
    expect(await stepAfterLogin()).toBe("complete");
  });

  it("prompts again when the app asks for more than was consented to", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser user/Observation.rs",
      challenge: (await pkcePair()).challenge,
    });
    const state = (await (
      await login(stack, session, {
        username: "clinician",
        password: TEST_PASSWORD,
      })
    ).json()) as { step: string };

    expect(state.step).toBe("consent");
  });
});

describeWithDatabase("an endpoint that approves automatically", () => {
  let stack: TestStack;

  beforeAll(async () => {
    stack = await createTestStack({
      endpoint: {
        slug: "fhir",
        name: "Auto",
        fhirBaseUrl: "https://fhir.test/R4",
        isProduction: false,
        consentMode: "auto",
      },
    });
  });

  afterAll(async () => {
    await stack.close();
  });

  it("completes straight from login", async () => {
    const session = await startAuthorization(stack, {
      clientId: stack.publicClient.clientId,
      scope: "openid fhirUser",
      challenge: (await pkcePair()).challenge,
    });
    const state = (await (
      await login(stack, session, {
        username: "clinician",
        password: TEST_PASSWORD,
      })
    ).json()) as { step: string; redirectTo: string };

    expect(state.step).toBe("complete");
    expect(new URL(state.redirectTo).searchParams.get("code")).not.toBeNull();
  });
});
