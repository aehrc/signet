/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Puts the patient a permission ticket names into the stack's FHIR server.
 *
 * Separate from `scripts/seedStack.mjs`, and it has to be. That script runs as a
 * compose service *before* Pathling starts, because Pathling resolves its issuer
 * eagerly and exits if the endpoint behind it does not answer - so it cannot write
 * to a server that is not up yet. This one runs after, from the host, and
 * `e2e/globalSetup.ts` is what runs it.
 *
 * What it writes is one Patient carrying an IHI. That is the whole fixture, and it
 * exists because permission ticket exchange resolves the ticket's subject by
 * searching the endpoint's FHIR server for exactly one patient with that
 * identifier: zero matches refuses the exchange, and so does more than one. Without
 * a real patient there is nothing to prove but the refusal.
 *
 * It writes through Signet rather than around it: a client credentials token from
 * the seeded `stub-writer` client, whose write is permitted by the endpoint's
 * policy and by its own allowlist and by nothing else. So the seed also exercises
 * the write half of the Pathling preset, which no other command does.
 *
 * Idempotent: `PUT Patient/{id}` with a fixed id creates or replaces, so running it
 * over an already-seeded stack changes nothing observable.
 *
 * No dependencies: plain `fetch` against a stack that is already up. Run
 * `bun run stack:up` first.
 *
 * Author: John Grimes
 */

/**
 * Reads a variable, treating an empty value as absent.
 *
 * An exported-but-cleared variable arrives as an empty string, and reading that as
 * a port would produce `http://localhost:/fhir`.
 *
 * @param name - the variable to read.
 * @returns the value, or `undefined` if it is unset or empty.
 */
function setting(name) {
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

// The same variables `scripts/seedStack.mjs` reads, and for the same reason: the
// ports have to be *exported* into the shell, because Bun does not pass what it
// loaded from a `.env` file to the processes it spawns.
const SIGNET_PORT = setting("SIGNET_PORT") ?? "3000";
const PATHLING_PORT = setting("PATHLING_PORT") ?? "8080";

const BASE = setting("SIGNET_BASE_URL") ?? `http://localhost:${SIGNET_PORT}`;
const TENANT = setting("SIGNET_SEED_TENANT") ?? "demo";
const FHIR_BASE =
  setting("SIGNET_SEED_FHIR_BASE") ?? `http://localhost:${PATHLING_PORT}/fhir`;

/** The client `scripts/seedStack.mjs` registers for this, and nothing else. */
const WRITER_CLIENT_ID = "stub-writer";
const WRITER_SECRET = "stub-writer-secret-value-00000";

/**
 * The identifier system the connectathon programme's ticket subjects use.
 *
 * Matched exactly by the exchange grant, which treats the system as opaque - so a
 * ticket minted in another system finds no patient here, which is the refusal
 * rather than a cross-system guess.
 */
export const SUBJECT_SYSTEM = "http://ns.electronichealth.net.au/id/hi/ihi/1.0";

/** The IHI the suite's tickets name. Matches `apps/server/src/test/trustAnchor.ts`. */
export const SUBJECT_IHI = "8003608500314687";

/** The resource id the patient is written under, and the launch context it becomes. */
export const SUBJECT_PATIENT_ID = "ticket-subject";

/** The patient a ticket's subject identifier resolves to. */
const SUBJECT_PATIENT = {
  resourceType: "Patient",
  id: SUBJECT_PATIENT_ID,
  identifier: [{ system: SUBJECT_SYSTEM, value: SUBJECT_IHI }],
  name: [{ family: "Ticketsubject", given: ["Tessa"] }],
  gender: "female",
  birthDate: "1980-01-01",
};

/**
 * Obtains a token that may write patients to this endpoint's FHIR server.
 *
 * Read as well as write: the seed verifies its own work with the same search the
 * exchange grant makes, which is the only check that proves the fixture is
 * findable rather than merely stored.
 *
 * @returns The access token.
 * @throws {Error} When the token endpoint refuses, which means the endpoint's
 *   policy or the client's allowlist has been changed out from under this script.
 */
async function writerToken() {
  const response = await fetch(`${BASE}/t/${TENANT}/e/pathling/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${WRITER_CLIENT_ID}:${WRITER_SECRET}`).toString("base64")}`,
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      // Named exactly rather than as `system/Patient.cruds`: the preset's write
      // rule matches `system/*.cud` without narrowing, so a wider request is
      // granted the read half alone and the write fails much later.
      scope: "system/Patient.cud system/Patient.rs",
    }),
  });
  const body = await response.json();
  if (!response.ok || typeof body.access_token !== "string") {
    throw new Error(
      `could not obtain a write token for ${WRITER_CLIENT_ID}: ${response.status} ${JSON.stringify(body)}`,
    );
  }
  return body.access_token;
}

/**
 * Writes one resource, replacing whatever was there.
 *
 * @param accessToken - The credential to present.
 * @param resource - The resource, which must carry an id.
 * @throws {Error} When the server refuses the write.
 */
async function put(accessToken, resource) {
  const url = `${FHIR_BASE}/${resource.resourceType}/${resource.id}`;
  const response = await fetch(url, {
    method: "PUT",
    headers: {
      "content-type": "application/fhir+json",
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(resource),
  });
  if (!response.ok) {
    throw new Error(
      `could not write ${url}: ${response.status} ${await response.text()}`,
    );
  }
  console.log(`wrote ${resource.resourceType}/${resource.id}`);
}

/**
 * Makes the same search the exchange grant makes, and insists on one match.
 *
 * @param accessToken - The credential to present.
 * @throws {Error} When the identifier resolves to anything other than one patient,
 *   because that is the state in which the exchange scenario would fail with a
 *   refusal that looks like a product bug.
 */
async function assertResolvesToOnePatient(accessToken) {
  const query = new URLSearchParams({
    identifier: `${SUBJECT_SYSTEM}|${SUBJECT_IHI}`,
  });
  const response = await fetch(`${FHIR_BASE}/Patient?${query.toString()}`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(
      `could not search for the ticket subject: ${response.status} ${await response.text()}`,
    );
  }
  const bundle = await response.json();
  const matches = (bundle.entry ?? []).filter(
    (entry) => entry.resource?.resourceType === "Patient",
  );
  if (matches.length !== 1) {
    throw new Error(
      `IHI ${SUBJECT_IHI} matches ${matches.length} patients, and a permission ticket resolves only when it matches exactly one`,
    );
  }
  console.log(
    `IHI ${SUBJECT_IHI} resolves to Patient/${matches[0].resource.id}`,
  );
}

const accessToken = await writerToken();
await put(accessToken, SUBJECT_PATIENT);
await assertResolvesToOnePatient(accessToken);

console.log(`\nSeeded ${FHIR_BASE}`);
