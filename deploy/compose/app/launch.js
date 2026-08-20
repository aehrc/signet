/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * A SMART App Launch client, in about a hundred lines and no dependencies.
 *
 * It does the three things an app must do, and no more: discover the endpoints
 * from the issuer, navigate the browser to `/authorize` with a PKCE challenge,
 * and exchange the returned code for a token. Then it shows what came back, so a
 * test can assert on the scopes granted, the launch context, and the claims a
 * FHIR server would read.
 *
 * Both launch modes work. An EHR launch arrives with `iss` and `launch` in the
 * query; a standalone launch is started by opening this page with `?iss=...`
 * alone. The difference is one parameter, which is the point - a bug that breaks
 * one and not the other shows up as a failing test rather than as a difference
 * nobody noticed.
 *
 * The verifier is kept in `sessionStorage` because the redirect is a full page
 * load and there is nowhere else for it to live. It is a per-tab value that never
 * leaves the browser, which is exactly what PKCE asks for.
 *
 * Author: John Grimes
 */

const STORAGE_KEY = "signet-stub-app";

/** Writes to one of the page's panels. */
function show(testId, value) {
  const element = document.querySelector(`[data-testid="${testId}"]`);
  if (element !== null) {
    element.textContent =
      typeof value === "string" ? value : JSON.stringify(value, null, 2);
  }
}

/** Base64url without padding, which is what OAuth and JOSE both want. */
function base64Url(bytes) {
  return btoa(String.fromCodePoint(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

/** A PKCE verifier and its S256 challenge. */
async function pkcePair() {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(48)));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64Url(new Uint8Array(digest)) };
}

/** Decodes a JWT payload without verifying it. The suite asserts on claims. */
function decodeClaims(token) {
  const payload = token.split(".", 2)[1];
  if (payload === undefined) {
    return { error: "not a JWT" };
  }
  return JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(
        atob(payload.replaceAll("-", "+").replaceAll("_", "/")),
        (character) => character.codePointAt(0),
      ),
    ),
  );
}

/** Reads the app's configuration from the query string. */
function readParameters() {
  const query = new URLSearchParams(globalThis.location.search);
  return {
    iss: query.get("iss"),
    launch: query.get("launch"),
    code: query.get("code"),
    error: query.get("error"),
    errorDescription: query.get("error_description"),
    state: query.get("state"),
    clientId: query.get("client_id") ?? "stub-app",
    scope:
      query.get("scope") ??
      "openid fhirUser launch/patient patient/*.rs offline_access",
  };
}

/** Starts an authorization: discover, then navigate. */
async function beginLaunch(parameters) {
  show("status", "Discovering…");
  const response = await fetch(
    `${parameters.iss}/.well-known/smart-configuration`,
  );
  if (!response.ok) {
    show("status", `Discovery failed: ${response.status}`);
    return;
  }
  const configuration = await response.json();
  const { verifier, challenge } = await pkcePair();
  const state = base64Url(crypto.getRandomValues(new Uint8Array(16)));

  sessionStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      verifier,
      state,
      iss: parameters.iss,
      clientId: parameters.clientId,
      tokenEndpoint: configuration.token_endpoint,
      // Kept because the redirect back carries only `code` and `state`: the
      // `aud` the launch was started with is gone from the URL by the time the
      // token has been exchanged, and that is when the FHIR server is called.
      fhirBase: fhirBaseFrom(),
    }),
  );

  const url = new URL(configuration.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", parameters.clientId);
  url.searchParams.set("redirect_uri", redirectUri());
  url.searchParams.set("scope", parameters.scope);
  url.searchParams.set("state", state);
  url.searchParams.set("aud", configuration.aud ?? fhirBaseFrom(configuration));
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (parameters.launch !== null) {
    url.searchParams.set("launch", parameters.launch);
  }

  show("status", "Redirecting to the authorization server…");
  globalThis.location.assign(url.toString());
}

/** This page, with no query string. Registered as the client's redirect URI. */
function redirectUri() {
  return `${globalThis.location.origin}${globalThis.location.pathname}`;
}

/**
 * The FHIR server the token should be minted for.
 *
 * Signet validates `aud` against the endpoint's configured FHIR base URL, so a
 * launch that guesses it wrong is refused. The value is not in the discovery
 * document, so the app is told it - which is what a real app is too, at
 * registration time.
 *
 * Only meaningful while `aud` is still in the address bar, which is to say
 * before the redirect back. The value is stashed in the launch session for the
 * half of the flow that happens after it; the fallback here is the default port
 * this stack publishes Pathling on, and is wrong for a stack moved off it.
 */
function fhirBaseFrom() {
  return (
    new URLSearchParams(globalThis.location.search).get("aud") ??
    "http://localhost:8080/fhir"
  );
}

/** Finishes an authorization: exchange the code, then show everything. */
async function completeLaunch(parameters) {
  const stored = sessionStorage.getItem(STORAGE_KEY);
  if (stored === null) {
    show("status", "No launch in progress in this tab.");
    return;
  }
  const session = JSON.parse(stored);
  if (parameters.state !== session.state) {
    // The state check belongs to the app, not to the authorization server: it is
    // what stops another site's response being fed into this tab.
    show("status", "State did not match. Refusing to continue.");
    return;
  }

  show("status", "Exchanging the code…");
  const response = await fetch(session.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: parameters.code,
      redirect_uri: redirectUri(),
      client_id: session.clientId,
      code_verifier: session.verifier,
    }).toString(),
  });

  const body = await response.json();
  show("token-response", body);
  if (!response.ok) {
    show("status", `Token request failed: ${response.status}`);
    return;
  }

  show("access-token-claims", decodeClaims(body.access_token));
  show("status", "Launch complete.");
  sessionStorage.removeItem(STORAGE_KEY);

  await callFhirServer(body.access_token, session.fhirBase);
}

/**
 * Uses the token, which is the only proof that any of this worked.
 *
 * A token that a FHIR server rejects is a token the app cannot use, and no
 * assertion about its claims substitutes for asking the server.
 */
async function callFhirServer(accessToken, fhirBase) {
  // A bare search, and the same one whether or not a patient is in context. The
  // question this asks is "does the FHIR server accept this token", and the
  // server behind this stack is an analytics server: it implements neither
  // instance reads nor `_id`, and a request it answers with "not supported"
  // would tell us nothing about the token. Which patient the token is for is
  // asserted from the token response instead.
  const url = `${fhirBase ?? fhirBaseFrom()}/Patient?_count=1`;
  try {
    const response = await fetch(url, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/fhir+json",
      },
    });
    show("fhir-status", `${url} answered ${response.status}`);
    const body = await response.text();
    show("fhir-response", body.slice(0, 2000));
  } catch (error) {
    show("fhir-status", `${url} could not be reached: ${String(error)}`);
  }
}

const parameters = readParameters();

if (parameters.error !== null) {
  show(
    "status",
    `Refused: ${parameters.error} - ${parameters.errorDescription ?? ""}`,
  );
} else if (parameters.code !== null) {
  await completeLaunch(parameters);
} else if (parameters.iss === null) {
  show("status", "Open this page with ?iss=… to start a launch.");
} else {
  await beginLaunch(parameters);
}
