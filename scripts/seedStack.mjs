/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Seeds the compose stack with the endpoint, policy, client and accounts the
 * end-to-end suite launches against.
 *
 * Through the admin API rather than by writing rows, for the same reason the
 * integration suites go through it: the seed then exercises the route an operator
 * uses, and a change that breaks endpoint creation breaks the seed rather than
 * being discovered later by a test that cannot explain itself.
 *
 * Idempotent. Re-running it against a stack that is already seeded reports what
 * was already there and changes nothing, so it can be run before every suite
 * without tearing the stack down.
 *
 * No dependencies: plain `fetch` against a stack that is already up. Run
 * `bun run stack:up` first.
 *
 * Author: John Grimes
 */

import { readFileSync, readdirSync } from "node:fs";

/** The variables that move the stack, and that only the shell can carry. */
const PORT_VARIABLES = ["SIGNET_PORT", "PATHLING_PORT", "APP_PORT"];

/**
 * Refuses to seed when a port variable was declared in a `.env` file.
 *
 * Bun loads a `.env` file into this process and does not pass what it loaded to the
 * processes it spawns, so a port declared in one moves the URLs this script stores
 * while leaving the ports `docker compose` publishes at their defaults. The result
 * is an endpoint pointing at a Pathling nobody served, and a suite failing a long
 * way from the cause.
 *
 * Refusing rather than warning, because there is no reading of a port in a `.env`
 * file under which this script should carry on: it is either the value compose
 * used, in which case the shell has it too and the file is redundant, or it is not,
 * in which case seeding writes the wrong URLs.
 *
 * Nothing to do inside the container, which has no such files.
 *
 * @throws {Error} if a `.env` file in the working directory declares one.
 */
function refuseFileSourcedPorts() {
  // `.env` and `.env.<something>`, which is the shape of every file Bun loads, and
  // deliberately not everything beginning with `.env`: `.envrc` is direnv's, and
  // what direnv declares *is* exported into the shell - so it reaches compose and
  // Playwright, and refusing it would refuse the workflow the README recommends.
  // `.env.example` is documentation, and is the one `.env.` file Bun never loads.
  const files = readdirSync(".").filter(
    (name) =>
      (name === ".env" || name.startsWith(".env.")) && name !== ".env.example",
  );
  for (const file of files) {
    // Read through a symlink, which Bun does, but tolerate the two things that are
    // not a port in a file: a directory whose name fits the pattern, and a symlink
    // pointing at nothing.
    let contents;
    try {
      contents = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const declared = PORT_VARIABLES.filter((name) =>
      new RegExp(String.raw`^[ \t]*(export[ \t]+)?${name}[ \t]*=`, "m").test(
        contents,
      ),
    );
    if (declared.length > 0) {
      throw new Error(
        `${file} declares ${declared.join(", ")}, where it does nothing. ` +
          `Bun loads that file into this script but not into \`docker compose\`, ` +
          `so the stack would keep its default ports while this seed wrote the ` +
          `moved ones. Remove ${declared.length === 1 ? "it" : "them"} from ` +
          `${file} and export ${declared.length === 1 ? "it" : "them"} instead: ` +
          `\`export ${declared.map((name) => `${name}=...`).join(" ")}\`. ` +
          `See the repository's .env.example.`,
      );
    }
  }
}

refuseFileSourcedPorts();

/**
 * Reads a variable, treating an empty value as absent.
 *
 * An exported-but-cleared variable arrives as an empty string, and reading that
 * as a port would produce `http://localhost:/fhir`.
 *
 * @param name - the variable to read.
 * @returns the value, or `undefined` if it is unset or empty.
 */
function setting(name) {
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

// The ports the compose stack publishes on. Duplicated from `e2e/src/stackUrls.ts`
// rather than imported: this script runs as bare `node` inside the runtime image,
// which ships no `node_modules`, so it can import nothing. The three
// `SIGNET_SEED_*` and `SIGNET_BASE_URL` variables below win where they are set,
// and compose sets all of them - so the ports matter only when a developer runs
// `bun run stack:seed` from the host.
//
// These have to be *exported* into the shell to have any effect: Bun does not pass
// a variable it loaded from a `.env` file to the processes it spawns.
const SIGNET_PORT = setting("SIGNET_PORT") ?? "3000";
const PATHLING_PORT = setting("PATHLING_PORT") ?? "8080";
const APP_PORT = setting("APP_PORT") ?? "4000";

const BASE = setting("SIGNET_BASE_URL") ?? `http://localhost:${SIGNET_PORT}`;
const TENANT = setting("SIGNET_SEED_TENANT") ?? "demo";
const EMAIL = setting("SIGNET_BOOTSTRAP_EMAIL") ?? "ops@example.org";
const PASSWORD =
  setting("SIGNET_BOOTSTRAP_PASSWORD") ?? "correct horse battery staple";

/** Where Pathling serves FHIR, as the browser reaches it. */
const FHIR_BASE =
  setting("SIGNET_SEED_FHIR_BASE") ?? `http://localhost:${PATHLING_PORT}/fhir`;

/** Where the stub SMART app is served. */
const APP_ORIGIN =
  setting("SIGNET_SEED_APP_ORIGIN") ?? `http://localhost:${APP_PORT}`;

/** The end user the suite signs in as. */
export const SEED_USER = {
  username: "clinician",
  password: "clinician-password",
};

/**
 * The console identity the suite reads the console with but cannot write through.
 *
 * Created by the compose stack's `bootstrap-viewer` service, because the admin API
 * deliberately has no route that creates a console account. This script only sets
 * its role.
 */
const VIEWER_EMAIL =
  process.env["SIGNET_SEED_VIEWER_EMAIL"] ?? "viewer@example.org";

/**
 * The console identity the passkey journey uses, and nothing else does.
 *
 * That journey signs out, which revokes the session the other console tests hold
 * in their saved storage state - so it cannot share an identity with them. Created
 * by the compose stack's `bootstrap-passkey` service, for the same reason the
 * viewer is: no admin API route makes a console account.
 */
const PASSKEY_EMAIL =
  process.env["SIGNET_SEED_PASSKEY_EMAIL"] ?? "passkeys@example.org";

let cookie = "";

/** Makes an admin API request, carrying the session cookie once there is one. */
async function api(method, path, body) {
  const response = await fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(cookie === "" ? {} : { cookie }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return response;
}

/**
 * Creates something, tolerating the case where it is already there.
 *
 * A 409 is success for a seed: the point is that the thing exists afterwards, not
 * that this run is what created it.
 */
async function ensure(description, method, path, body) {
  const response = await api(method, path, body);
  if (response.ok) {
    console.log(`created ${description}`);
    return await response.json().catch(() => {});
  }
  if (response.status === 409) {
    console.log(`${description} already exists`);
    return;
  }
  throw new Error(
    `could not create ${description}: ${response.status} ${await response.text()}`,
  );
}

/** Signs in and keeps the session cookie for everything that follows. */
async function signIn() {
  const response = await fetch(`${BASE}/api/v1/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!response.ok) {
    throw new Error(
      `could not sign in as ${EMAIL}: ${response.status} ${await response.text()}`,
    );
  }
  cookie = (response.headers.get("set-cookie") ?? "").split(";", 1)[0] ?? "";
  if (cookie === "") {
    throw new Error("sign-in returned no session cookie");
  }
}

/**
 * The Pathling preset, fetched from the server that ships it.
 *
 * With one rule turned on. The preset ships `grant-system-write` disabled, which is
 * the right default - it is the only rule in the preset that names a write, and a
 * deployment should have to say so. This stack has to say so, because the
 * ticket-exchange scenario resolves a permission ticket's subject against a patient
 * that has to be *in* Pathling, and `scripts/seedFhir.mjs` is what puts it there.
 *
 * Turning it on rather than editing the preset, and turning on nothing else: what
 * the console offers an operator is unchanged, and the write reaches exactly one
 * seeded client, whose registration is the second half of the permission. See
 * `stub-writer` below.
 */
async function pathlingPolicy() {
  const response = await api("GET", "/presets");
  if (!response.ok) {
    throw new Error(`could not read the presets: ${response.status}`);
  }
  const { presets } = await response.json();
  const preset = presets.find((candidate) => candidate.id === "pathling");
  if (preset === undefined) {
    throw new Error("the deployment ships no Pathling preset");
  }
  const document = structuredClone(preset.policy);
  const systemWrite = document.scopeGrants.find(
    (grant) => grant.id === "grant-system-write",
  );
  if (systemWrite === undefined) {
    throw new Error("the Pathling preset has no grant-system-write rule");
  }
  systemWrite.enabled = true;
  return document;
}

await signIn();

const endpointPath = `/tenants/${TENANT}/endpoints/pathling`;

await ensure("the pathling endpoint", "POST", `/tenants/${TENANT}/endpoints`, {
  slug: "pathling",
  name: "Pathling",
  fhirBaseUrl: FHIR_BASE,
  // Non-production, so the suite can use a persona and pick a patient that is
  // not on the account's list. A production endpoint would refuse both.
  isProduction: false,
  consentMode: "always",
  supportsBackendServices: true,
  supportsStyling: true,
  supportsStandaloneEncounterContext: true,
  supportsDynamicRegistration: true,
});

/**
 * Turns the developer portal on, for a stack that already had the endpoint.
 *
 * `ensure` above tolerates a 409 and changes nothing, which is what makes the seed
 * idempotent - and also what means a flag added to its body never reaches a stack
 * seeded before the flag existed. The capability is what the registration-request
 * fixtures below depend on, so it is restated rather than assumed.
 *
 * It changes no discovery document: `registration_endpoint` follows the endpoint's
 * trust anchor rule, not this flag, which `packages/core/src/discovery/build.test.ts`
 * pins and `e2e/tests/trust.spec.ts` measures.
 */
async function acceptSelfServeRegistration() {
  const response = await api("PATCH", endpointPath, {
    supportsDynamicRegistration: true,
  });
  if (!response.ok) {
    throw new Error(
      `could not turn the developer portal on: ${response.status} ${await response.text()}`,
    );
  }
  console.log("the endpoint accepts self-serve registration requests");
}

await acceptSelfServeRegistration();

/**
 * Pathling verifies tokens with Spring Security's default JWT decoder, which
 * accepts RS256 and nothing else. Signet's default key is ES384, which that
 * decoder rejects with "another algorithm expected" - a message that sends an
 * operator looking at their keys rather than at a default they cannot see. So the
 * endpoint is given an RS256 key and promoted to it, which is the whole of what
 * putting Signet in front of Pathling requires.
 */
async function useRs256() {
  const keys = await api("GET", `${endpointPath}/keys`);
  const { keys: existing } = await keys.json();
  if (
    existing.some((key) => key.algorithm === "RS256" && key.status === "active")
  ) {
    console.log("the endpoint already signs with RS256");
    return;
  }
  await ensure("an RS256 signing key", "POST", `${endpointPath}/keys`, {
    algorithm: "RS256",
  });
  const promoted = await api("POST", `${endpointPath}/keys/promote`);
  if (!promoted.ok) {
    throw new Error(
      `could not promote the RS256 key: ${promoted.status} ${await promoted.text()}`,
    );
  }
  console.log("promoted the RS256 signing key");
}

await useRs256();

// The endpoint ships with the SMART baseline; the suite is about Pathling's
// authorities, so the policy is replaced and published in one request.
await ensure("the Pathling policy", "POST", `${endpointPath}/policies`, {
  document: await pathlingPolicy(),
  note: "Seeded by scripts/seedStack.mjs for the end-to-end suite.",
  publish: true,
});

await ensure("the stub app client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-app",
  name: "Stub SMART app",
  clientType: "public",
  redirectUris: [`${APP_ORIGIN}/`],
  launchUri: `${APP_ORIGIN}/`,
  grantTypes: ["authorization_code", "refresh_token"],
  allowedScopes: [
    "openid",
    "fhirUser",
    "profile",
    "launch",
    "launch/patient",
    "launch/encounter",
    "offline_access",
    "patient/*.rs",
    "user/*.rs",
  ],
});

await ensure("a backend service client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-backend",
  name: "Stub backend service",
  clientType: "confidential-symmetric",
  secret: "stub-backend-secret-value-0000",
  grantTypes: ["client_credentials"],
  allowedScopes: ["system/*.rs"],
});

/**
 * The one client on this stack that may write to Pathling.
 *
 * `scripts/seedFhir.mjs` uses it, and nothing else does. It is separate from
 * `stub-backend` deliberately: that client's allowlist is `system/*.rs`, and
 * `launch.spec.ts` asserts that asking it for `system/*.cud` is refused - so
 * widening it would delete a test rather than pass one.
 *
 * The write it can do is bounded twice, by the endpoint's policy (the
 * `grant-system-write` rule above, which no other client asks for) and by this
 * allowlist.
 */
await ensure("a FHIR seeding client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-writer",
  name: "Stub FHIR seeder",
  clientType: "confidential-symmetric",
  secret: "stub-writer-secret-value-00000",
  grantTypes: ["client_credentials"],
  allowedScopes: ["system/*.cud", "system/*.rs"],
});

/**
 * A confidential client that holds a shared secret.
 *
 * It exists so the suite can cover the parts of SMART a public client cannot
 * reach. `offline_access` is granted to confidential clients only, so refresh -
 * and therefore refresh rotation, introspection of a live token, and revocation -
 * needs a client of this type. It also mints the launch handles for the EHR
 * launch, because the launch-context endpoint authenticates its caller as a
 * client registered for `authorization_code`.
 */
await ensure("a confidential client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-confidential",
  name: "Stub confidential app",
  clientType: "confidential-symmetric",
  secret: "stub-confidential-secret-value-0000",
  redirectUris: [`${APP_ORIGIN}/`],
  launchUri: `${APP_ORIGIN}/`,
  grantTypes: ["authorization_code", "refresh_token"],
  allowedScopes: [
    "openid",
    "fhirUser",
    "launch",
    "launch/patient",
    "offline_access",
    "patient/*.rs",
    "user/*.rs",
  ],
});

/**
 * A second confidential client, for the refresh-token reuse scenario alone.
 *
 * Reuse detection revokes every token the *client* holds, not merely the family
 * the replayed token belonged to - the conservative response, since at that point
 * Signet knows one of two holders is an attacker but not which. That makes the
 * scenario destructive to anything else using the same client, so it gets its own
 * rather than making the suite run serially to accommodate it.
 */
await ensure("a reuse-detection client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-reuse",
  name: "Stub confidential app (reuse detection)",
  clientType: "confidential-symmetric",
  secret: "stub-reuse-secret-value-0000",
  redirectUris: [`${APP_ORIGIN}/`],
  launchUri: `${APP_ORIGIN}/`,
  grantTypes: ["authorization_code", "refresh_token"],
  allowedScopes: [
    "openid",
    "fhirUser",
    "launch",
    "launch/patient",
    "offline_access",
    "patient/*.rs",
    "user/*.rs",
  ],
});

/**
 * A confidential client that authenticates with `private_key_jwt`.
 *
 * This is the SMART Backend Services credential proper: the client signs an
 * assertion rather than presenting a shared secret, so nothing reusable crosses
 * the wire. The public key is inline rather than behind a `jwks_uri` because the
 * suite is asserting the credential, not the key-fetching path.
 *
 * The key pair is fixed and lives in `e2e/support/keys.ts`. It is a test fixture
 * for a stack seeded with well-known passwords; it authenticates nothing anybody
 * would want.
 */
await ensure("an asymmetric client", "POST", `${endpointPath}/clients`, {
  clientId: "stub-asymmetric",
  name: "Stub asymmetric backend service",
  clientType: "confidential-asymmetric",
  grantTypes: ["client_credentials"],
  allowedScopes: ["system/*.rs"],
  jwks: {
    keys: [
      {
        kty: "EC",
        crv: "P-384",
        x: "Nu9Nk903rbfzH-6LCN_8clmcRHFRfub-o6mepu51nEaafbnS0ZmjlzWCQYSk2c4m",
        y: "2Je25QiKuJGBGAoeNZXU5Ax-qrXbLDYMXgAkTTOOM3zqCtD98J2JEScC7UufEcNz",
        alg: "ES384",
        use: "sig",
        kid: "stub-asymmetric-1",
      },
    ],
  },
});

/**
 * The registration requests the console's queue is measured against.
 *
 * The queue was the one console route whose only reachable state was empty: the
 * endpoint accepted no self-serve requests, so no request could exist, and a page
 * measured empty proves nothing about the page an administrator actually reads. So
 * the stack files two - one waiting for a decision, one already refused - and the
 * mobile sweep meets a populated queue rather than a placeholder.
 *
 * Their values are long and every one of them is legal. The schema in
 * `packages/contracts/src/admin/clients.ts` permits a 320-character contact address,
 * a 2048-character launch URI, a 2048-character redirect URI and a 2000-character
 * note, and a layout that only holds for short values is a layout that breaks on the
 * first real submission rather than on a contrived one. Each value below states the
 * limit it sits under.
 *
 * The refused one carries a long decision note, which is the only way the portal's
 * "Note from the reviewer" and the console's decided row can be seen at all.
 */
const LONG_REQUEST_NAME =
  "Regional Immunisation Registry Synchronisation Connector";

/** The refused request, named so the decided row is identifiable in a test. */
const REFUSED_REQUEST_NAME = "Population Analytics Extract Scheduler";

/** A contact address of 246 characters, under the schema's limit of 320. */
const LONG_CONTACT_EMAIL =
  "registration.requests.and.integration.enquiries.for.the.regional.immunisation.registry@" +
  "digital-health-integration-services.population-health-programmes.regional-immunisation-registry." +
  "health-informatics-and-interoperability-directorate.example.org";

/** A launch URI of 493 characters, under the schema's limit of 2048. */
const LONG_LAUNCH_URI =
  `${APP_ORIGIN}/launch/immunisation-registry-synchronisation-connector` +
  "?deployment=regional-immunisation-registry-production-a" +
  "&workflow=scheduled-bidirectional-record-synchronisation" +
  "&profile=au-core-immunisation-record-exchange-profile-v2" +
  "&correlation=8f1c2b0e-4a6d-4f2c-9b3e-7d5a1c0e6f48-9a2b3c4d5e6f7081" +
  "&audience=" +
  encodeURIComponent(`${BASE}/t/${TENANT}/e/pathling`) +
  "&notes=" +
  encodeURIComponent(
    "opened by the electronic medical record when a clinician reviews an immunisation history",
  );

/** A redirect URI of 157 characters, under the schema's limit of 2048. */
const LONG_REDIRECT_URI =
  `${APP_ORIGIN}/oauth2/callback/immunisation-registry-synchronisation-connector` +
  "/regional-immunisation-registry-production-a/authorization-code-response";

/** A scope of 127 characters, under the schema's limit of 256. */
const LONG_SCOPE =
  "patient/Immunization.rs?category=" +
  "http://terminology.hl7.org/CodeSystem/observation-category|laboratory-and-immunisation-records";

/** A note of 1027 characters, under the schema's limit of 2000. */
const LONG_NOTE =
  "The connector reconciles immunisation records between the regional registry and " +
  "the practices that submit to it, so that a clinician reviewing a patient's history " +
  "sees the same doses whichever system they are looking at. It reads immunisation " +
  "records and the patient demographics needed to match them, and it writes nothing. " +
  "Each synchronisation run is initiated by the practice's own scheduler, and the " +
  "software statement issued to that deployment is " +
  "eyJhbGciOiJFUzM4NCIsImtpZCI6InJlZ2lvbmFsLWltbXVuaXNhdGlvbi1yZWdpc3RyeS0yMDI2LTA4In0" +
  ".eyJzb2Z0d2FyZV9pZCI6ImltbXVuaXNhdGlvbi1yZWdpc3RyeS1zeW5jaHJvbmlzYXRpb24tY29ubmVjdG9yIn0" +
  ", which the registry's operators can verify against the published keys. The " +
  "deployment identifier the request should be recorded against is " +
  "regional-immunisation-registry-production-a-0f3d9c81b47e5a26. We are asking for the " +
  "narrowest set of scopes the reconciliation needs, and we are happy for the launch " +
  "URI to be narrowed further before approval if the endpoint's operators would prefer " +
  "a shorter one.";

/** A decision note of 536 characters, under the schema's limit of 2000. */
const LONG_DECISION_NOTE =
  "Refused for now, and the reason is the extract rather than the requester: a " +
  "scheduled population-level extract is a different permission from the " +
  "record-by-record access this endpoint's policy grants, and it needs the data " +
  "custodian's agreement before an administrator can hand it out. The reference to " +
  "quote when that agreement is in place is " +
  "population-analytics-extract-scheduler-0b7f4e29d5c81a63-review-2026-08, and the " +
  "request can then be filed again against the same contact address. Nothing about the " +
  "submission itself was wrong.";

/**
 * Files a registration request through the developer portal, once.
 *
 * Idempotent by name, because the portal mints an identifier per submission and has
 * no notion of the same request twice: a seed that simply posted would add a row to
 * the queue on every run, and the queue is a thing a test reads.
 *
 * @param name - The request's app name, which is also its identity for this seed.
 * @param payload - The rest of the submission.
 * @returns The request as the console sees it, or `undefined` if it was already
 *   there - the tracking token is minted once and cannot be recovered on a later run.
 */
async function fileRequest(name, payload) {
  const listed = await api("GET", `${endpointPath}/client-requests`);
  if (!listed.ok) {
    throw new Error(
      `could not read the registration requests: ${listed.status} ${await listed.text()}`,
    );
  }
  const { requests } = await listed.json();
  const existing = requests.find((request) => request.payload.name === name);
  if (existing !== undefined) {
    console.log(`the "${name}" registration request already exists`);
    return existing;
  }

  const response = await fetch(`${BASE}/t/${TENANT}/e/pathling/apps/requests`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, ...payload }),
  });
  if (!response.ok) {
    throw new Error(
      `could not file the "${name}" registration request: ${response.status} ${await response.text()}`,
    );
  }
  console.log(`filed the "${name}" registration request`);
  const { request } = await response.json();
  return request;
}

await fileRequest(LONG_REQUEST_NAME, {
  clientType: "public",
  redirectUris: [`${APP_ORIGIN}/`, LONG_REDIRECT_URI],
  launchUri: LONG_LAUNCH_URI,
  requestedScopes: [
    "openid",
    "fhirUser",
    "launch/patient",
    "patient/Immunization.rs",
    LONG_SCOPE,
  ],
  contactEmail: LONG_CONTACT_EMAIL,
  note: LONG_NOTE,
});

const refused = await fileRequest(REFUSED_REQUEST_NAME, {
  clientType: "confidential-symmetric",
  redirectUris: [`${APP_ORIGIN}/`],
  requestedScopes: ["system/Observation.rs", "system/Patient.rs"],
  contactEmail: LONG_CONTACT_EMAIL,
  note: "A nightly extract of immunisation coverage by postcode, for the regional programme's reporting.",
});

if (refused !== undefined && refused.status === "pending") {
  const rejected = await api(
    "POST",
    `${endpointPath}/client-requests/${refused.id}/reject`,
    { decisionNote: LONG_DECISION_NOTE },
  );
  if (!rejected.ok) {
    throw new Error(
      `could not refuse the "${REFUSED_REQUEST_NAME}" request: ${rejected.status} ${await rejected.text()}`,
    );
  }
  console.log(`refused the "${REFUSED_REQUEST_NAME}" registration request`);
}

await ensure("the clinician account", "POST", `${endpointPath}/users`, {
  username: SEED_USER.username,
  password: SEED_USER.password,
  displayName: "Dr Casey Clinician",
  fhirUserReference: "Practitioner/clinician-1",
  roles: ["clinician"],
});

/**
 * Sets a console identity's role in the seeded tenant.
 *
 * Downgraded rather than created here: no admin API route makes a console
 * identity, so the compose stack's bootstrap services create these and they arrive
 * as owners. A PUT is idempotent, so re-seeding simply restates the role.
 *
 * A stack bootstrapped without the identity is reported rather than fatal - only
 * one test needs each of them, and a developer running the seed against a partial
 * stack should be told which one is missing rather than stopped.
 */
async function setMembership(email, role) {
  const response = await api("PUT", `/tenants/${TENANT}/members`, {
    email,
    role,
  });
  if (response.ok) {
    console.log(`set ${email} to ${role}`);
    return;
  }
  if (response.status === 404) {
    console.log(`no console account for ${email}; skipping its membership`);
    return;
  }
  throw new Error(
    `could not set ${email} to ${role}: ${response.status} ${await response.text()}`,
  );
}

await setMembership(VIEWER_EMAIL, "viewer");
// The passkey journey only reads the console; what it exercises is the account
// menu and the dialog behind it, neither of which depends on a role.
await setMembership(PASSKEY_EMAIL, "viewer");

await ensure("a patient persona", "POST", `${endpointPath}/users`, {
  username: "pat",
  displayName: "Pat Patient",
  fhirUserReference: "Patient/pat-9",
  isPersona: true,
  defaultContext: { patient: "pat-9" },
});

console.log(`\nSeeded ${BASE}/t/${TENANT}/e/pathling`);
console.log(
  `Launch the stub app at ${APP_ORIGIN}/?iss=${BASE}/t/${TENANT}/e/pathling`,
);
