/**
 * Driving a whole authorization through the app, as an app and a browser would.
 *
 * The integration suites assert on outcomes, not on plumbing, so the plumbing lives
 * here: PKCE pairs, form posts, client assertions, and the three-step interaction.
 * Each helper does exactly what a real caller does - no repository is touched to
 * shortcut a step - which is what makes a suite built from them a genuine test of the
 * composition rather than of the helpers.
 *
 * Author: John Grimes
 */

import { computeS256Challenge } from "@signet/core";
import { SignJWT, importJWK } from "jose";

import { TEST_CLIENT_SECRET, TEST_PASSWORD } from "./harness.js";

import type { ClientFixture, TestStack } from "./harness.js";

/** A PKCE verifier and the challenge derived from it. */
export interface PkcePair {
  readonly verifier: string;
  readonly challenge: string;
}

/** Generates a PKCE pair with a verifier at the RFC 7636 maximum entropy. */
export async function pkcePair(
  seed = "signet-test-verifier",
): Promise<PkcePair> {
  // 43 characters minimum; padded deterministically so a failure is reproducible.
  const verifier = `${seed}${"-abcdefghijklmnopqrstuvwxyz".repeat(3)}`.slice(
    0,
    64,
  );
  return { verifier, challenge: await computeS256Challenge(verifier) };
}

/** The path prefix every request in these helpers is made under. */
export function issuerPath(stack: TestStack): string {
  return `/t/${stack.tenant.slug}/e/${stack.endpoint.slug}`;
}

/** Posts a form-encoded body, the way a token endpoint client does. */
export async function postForm(
  stack: TestStack,
  path: string,
  fields: Readonly<Record<string, string>>,
  headers: Readonly<Record<string, string>> = {},
): Promise<Response> {
  return await stack.app.request(`${issuerPath(stack)}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(fields).toString(),
  });
}

/** Posts a JSON body, the way the interaction pages do. */
export async function postJson(
  stack: TestStack,
  path: string,
  body: unknown,
): Promise<Response> {
  return await stack.app.request(`${issuerPath(stack)}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** An `Authorization: Basic` header built the RFC 6749 §2.3.1 way. */
export function basicAuth(
  clientId: string,
  secret = TEST_CLIENT_SECRET,
): string {
  const encoded = Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`,
    "utf8",
  ).toString("base64");
  return `Basic ${encoded}`;
}

/** What a `/authorize` request should ask for. */
export interface AuthorizeOptions {
  readonly clientId: string;
  readonly scope: string;
  readonly challenge: string;
  readonly redirectUri?: string;
  readonly state?: string;
  readonly aud?: string;
  readonly launch?: string;
  readonly nonce?: string;
  readonly responseType?: string;
  readonly codeChallengeMethod?: string;
  /** Sends the request as a form POST rather than a query-string GET. */
  readonly method?: "GET" | "POST";
}

/** Builds the query parameters for an `/authorize` request. */
function authorizeParameters(
  stack: TestStack,
  options: AuthorizeOptions,
): URLSearchParams {
  const parameters = new URLSearchParams({
    response_type: options.responseType ?? "code",
    client_id: options.clientId,
    redirect_uri: options.redirectUri ?? "https://app.test/cb",
    scope: options.scope,
    aud: options.aud ?? stack.endpoint.fhirBaseUrl,
    code_challenge: options.challenge,
    code_challenge_method: options.codeChallengeMethod ?? "S256",
  });
  if (options.state !== undefined) {
    parameters.set("state", options.state);
  }
  if (options.launch !== undefined) {
    parameters.set("launch", options.launch);
  }
  if (options.nonce !== undefined) {
    parameters.set("nonce", options.nonce);
  }
  return parameters;
}

/** Makes an `/authorize` request and returns the raw response. */
export async function authorize(
  stack: TestStack,
  options: AuthorizeOptions,
): Promise<Response> {
  const parameters = authorizeParameters(stack, options);
  if (options.method === "POST") {
    return await stack.app.request(`${issuerPath(stack)}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: parameters.toString(),
    });
  }
  return await stack.app.request(
    `${issuerPath(stack)}/authorize?${parameters.toString()}`,
  );
}

/**
 * Starts an authorization and returns the session identifier it created.
 *
 * @throws {Error} When the request did not redirect to a login page, so a suite
 *   that expected the happy path fails with the actual response rather than with a
 *   confusing `undefined` several lines later.
 */
export async function startAuthorization(
  stack: TestStack,
  options: AuthorizeOptions,
): Promise<string> {
  const response = await authorize(stack, options);
  const location = response.headers.get("location");
  if (response.status !== 302 || location === null) {
    throw new Error(
      `expected a redirect to the login page, got ${String(response.status)}: ${await response.text()}`,
    );
  }
  const session = new URL(location).searchParams.get("session");
  if (session === null) {
    throw new Error(`no session in the login redirect: ${location}`);
  }
  return session;
}

/** The interaction state the pages render from. */
export interface InteractionState {
  readonly step: string;
  readonly redirectTo?: string;
  readonly requestedScopes: readonly string[];
  readonly patients: readonly string[];
  readonly personas: readonly { readonly id: string }[];
}

/** Reads the current interaction state. */
export async function interactionState(
  stack: TestStack,
  sessionId: string,
): Promise<InteractionState> {
  const response = await stack.app.request(
    `${issuerPath(stack)}/interaction/${sessionId}`,
  );
  return (await response.json()) as InteractionState;
}

/** How the end user should authenticate. */
export type LoginAs =
  | { readonly username: string; readonly password: string }
  | { readonly personaId: string };

/** Signs in, as either a local account or a persona. */
export async function login(
  stack: TestStack,
  sessionId: string,
  as: LoginAs,
): Promise<Response> {
  return await postJson(stack, `/interaction/${sessionId}/login`, as);
}

/** Chooses a patient, and optionally an encounter. */
export async function selectContext(
  stack: TestStack,
  sessionId: string,
  chosen: { readonly patient?: string; readonly encounter?: string },
): Promise<Response> {
  return await postJson(stack, `/interaction/${sessionId}/context`, chosen);
}

/** Approves or declines the request. */
export async function decideConsent(
  stack: TestStack,
  sessionId: string,
  approve: boolean,
): Promise<Response> {
  return await postJson(stack, `/interaction/${sessionId}/consent`, {
    approve,
  });
}

/**
 * Walks the interaction to completion and returns the authorization code.
 *
 * Each step is driven from the state the previous one reported, exactly as a browser
 * would, so a suite using this cannot accidentally skip a step the server required.
 *
 * @throws {Error} When the interaction did not reach a redirect carrying a code.
 */
export async function completeInteraction(
  stack: TestStack,
  sessionId: string,
  options: { readonly as: LoginAs; readonly patient?: string },
): Promise<string> {
  let state = await interactionState(stack, sessionId);

  if (state.step === "login") {
    state = (await (
      await login(stack, sessionId, options.as)
    ).json()) as InteractionState;
  }
  if (state.step === "select-context") {
    const patient = options.patient ?? state.patients[0];
    if (patient === undefined) {
      throw new Error("the interaction wants a patient and none was offered");
    }
    state = (await (
      await selectContext(stack, sessionId, { patient })
    ).json()) as InteractionState;
  }
  if (state.step === "consent") {
    state = (await (
      await decideConsent(stack, sessionId, true)
    ).json()) as InteractionState;
  }

  if (state.step !== "complete" || state.redirectTo === undefined) {
    throw new Error(`interaction did not complete: ${JSON.stringify(state)}`);
  }
  const code = new URL(state.redirectTo).searchParams.get("code");
  if (code === null) {
    throw new Error(`no code in the completion redirect: ${state.redirectTo}`);
  }
  return code;
}

/**
 * Runs a whole authorization and returns the code and the verifier to redeem it.
 *
 * The single call most suites want: everything up to, but not including, the token
 * request.
 */
export async function authorizeToCode(
  stack: TestStack,
  options: Omit<AuthorizeOptions, "challenge"> & {
    readonly as?: LoginAs;
    readonly patient?: string;
  },
): Promise<{ readonly code: string; readonly verifier: string }> {
  const pkce = await pkcePair();
  const session = await startAuthorization(stack, {
    ...options,
    challenge: pkce.challenge,
  });
  const code = await completeInteraction(stack, session, {
    as: options.as ?? { username: "clinician", password: TEST_PASSWORD },
    ...(options.patient === undefined ? {} : { patient: options.patient }),
  });
  return { code, verifier: pkce.verifier };
}

/** What a client assertion should claim. */
export interface AssertionOptions {
  readonly jti?: string;
  readonly audience?: string;
  readonly expiresInSeconds?: number;
  readonly subject?: string;
  readonly issuer?: string;
  readonly algorithm?: "RS384" | "ES384";
}

/**
 * Signs a `private_key_jwt` client assertion with a fixture client's private key.
 *
 * @throws {Error} When the fixture has no private key, which means the caller picked
 *   a client that does not authenticate this way.
 */
export async function clientAssertion(
  stack: TestStack,
  fixture: ClientFixture,
  options: AssertionOptions = {},
): Promise<string> {
  if (fixture.privateJwk === undefined) {
    throw new Error(`${fixture.client.clientId} has no private key`);
  }
  const algorithm = options.algorithm ?? "RS384";
  const key = await importJWK(fixture.privateJwk, algorithm);
  const issuedAt = Math.floor(stack.context.clock().getTime() / 1000);

  return await new SignJWT({})
    .setProtectedHeader({ alg: algorithm })
    .setIssuer(options.issuer ?? fixture.client.clientId)
    .setSubject(options.subject ?? fixture.client.clientId)
    .setAudience(options.audience ?? `${stack.issuer}/token`)
    .setJti(options.jti ?? crypto.randomUUID())
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + (options.expiresInSeconds ?? 60))
    .sign(key);
}

/** Posts a `client_credentials` request authenticated with an assertion. */
export async function backendToken(
  stack: TestStack,
  scope: string,
  options: AssertionOptions = {},
): Promise<Response> {
  return await postForm(stack, "/token", {
    grant_type: "client_credentials",
    scope,
    client_assertion_type:
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: await clientAssertion(
      stack,
      stack.backendClient,
      options,
    ),
  });
}

/** Decodes a JWT payload without verifying it, for assertions about claims. */
export function decodePayload(token: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(token.split(".", 2)[1] ?? "", "base64url").toString("utf8"),
  ) as Record<string, unknown>;
}
