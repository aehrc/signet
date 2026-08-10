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
  const files = readdirSync(".", { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .filter(
      (name) =>
        (name === ".env" || name.startsWith(".env.")) &&
        name !== ".env.example",
    );
  for (const file of files) {
    const contents = readFileSync(file, "utf8");
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

/** The Pathling preset, fetched from the server that ships it. */
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
  return preset.policy;
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
});

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
