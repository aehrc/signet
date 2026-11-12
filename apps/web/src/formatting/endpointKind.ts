/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * How the console words and filters things by endpoint kind.
 *
 * An endpoint is either a SMART on FHIR issuer in front of a FHIR server, or a plain
 * OAuth 2.0 / OpenID Connect issuer for any other app or API. The kind is fixed at
 * creation, and almost every page has something that reads differently on the two:
 * what the audience is called, which discovery document an operator copies, which
 * capability flags exist at all, and which policy presets apply.
 *
 * Those decisions are made here, once, so that two pages cannot disagree about them.
 * Hiding a SMART-only control on an OAuth endpoint is not cosmetic: the API refuses
 * every one of them there, and offering it would only surface that refusal.
 *
 * Author: John Grimes
 */

import { discoveryUrl, SMART_ONLY_CAPABILITY_FLAGS } from "@signet/core";

import { capabilityLabel } from "./values.js";

import type { EndpointView, PresetView } from "../api/types.js";
import type { RuleList } from "../policy/rules.js";
import type { EndpointKind } from "@signet/core";

/** The SMART-only flags, as a set of the admin API's flag names. */
const SMART_ONLY: ReadonlySet<string> = new Set(SMART_ONLY_CAPABILITY_FLAGS);

/** What each kind is called. */
const KIND_LABELS: Readonly<Record<EndpointKind, string>> = {
  smart: "SMART on FHIR",
  oauth: "OAuth / OpenID Connect",
};

/**
 * Names an endpoint kind as the console shows it.
 *
 * @param kind - The endpoint's kind.
 * @example
 * endpointKindLabel("oauth"); // "OAuth / OpenID Connect"
 */
export function endpointKindLabel(kind: EndpointKind): string {
  return KIND_LABELS[kind];
}

/** One choice on the create form, with what it means. */
export interface EndpointKindOption {
  readonly value: EndpointKind;
  readonly label: string;
  readonly description: string;
}

/** The kinds the create form offers, in the order it offers them. */
export const ENDPOINT_KIND_OPTIONS: readonly EndpointKindOption[] = [
  {
    value: "smart",
    label: KIND_LABELS.smart,
    description:
      "SMART App Launch in front of a FHIR server: EHR and standalone launch, SMART scopes and launch context.",
  },
  {
    value: "oauth",
    label: KIND_LABELS.oauth,
    description:
      "Sign-in and access tokens for any other web app or API, with OpenID Connect identity scopes and the API's own scopes.",
  },
];

/** How the audience field and its value are described on one kind. */
export interface AudienceWording {
  readonly label: string;
  readonly hint: string;
  readonly placeholder: string;
  /** The phrase the endpoint header uses to say what the endpoint is for. */
  readonly fronting: (audience: string) => string;
}

/** The audience's wording, per kind. */
const AUDIENCE_WORDING: Readonly<Record<EndpointKind, AudienceWording>> = {
  smart: {
    label: "FHIR base URL",
    hint: "The server this endpoint fronts. Also the audience every access token is minted for.",
    placeholder: "https://fhir.example.org/fhir",
    fronting: (audience) => `fronting ${audience}`,
  },
  oauth: {
    label: "Audience",
    hint: "The aud every access token carries, which your API checks. Conventionally the API's base URL.",
    placeholder: "https://api.example.org",
    fronting: (audience) => `issuing tokens for ${audience}`,
  },
};

/**
 * How the audience is labelled and described on an endpoint of a kind.
 *
 * On a SMART endpoint the audience is the FHIR base URL, and is called that, because
 * that is what an operator has to hand. On an OAuth endpoint it is whatever the API
 * checks `aud` against.
 *
 * @param kind - The endpoint's kind.
 * @example
 * audienceWording("oauth").label; // "Audience"
 */
export function audienceWording(kind: EndpointKind): AudienceWording {
  return AUDIENCE_WORDING[kind];
}

/** The discovery document an operator gives the resource server. */
export interface DiscoveryDocument {
  readonly label: string;
  readonly url: string;
}

/**
 * What an endpoint's discovery document is called.
 *
 * @param kind - The endpoint's kind, or undefined where it is not known, as on a
 *   developer portal that has not yet learned it.
 * @example
 * discoveryLabel("oauth"); // "OpenID configuration"
 */
export function discoveryLabel(kind: EndpointKind | undefined): string {
  if (kind === undefined) {
    return "Discovery document";
  }
  return kind === "smart" ? "SMART configuration" : "OpenID configuration";
}

/**
 * The discovery document an endpoint publishes.
 *
 * A SMART endpoint's is its SMART configuration. An OAuth endpoint publishes none -
 * the API answers 404 there - so its OpenID configuration is the one to copy. The
 * URL comes from core's `discoveryUrl`, as the developer portal's does.
 *
 * @param endpoint - The endpoint, of which only the kind and issuer are read.
 * @example
 * discoveryDocument({ kind: "oauth", issuer }).label; // "OpenID configuration"
 */
export function discoveryDocument(
  endpoint: Pick<EndpointView, "kind" | "issuer">,
): DiscoveryDocument {
  return {
    label: discoveryLabel(endpoint.kind),
    url: discoveryUrl(endpoint.kind, endpoint.issuer),
  };
}

/**
 * The capability flags an endpoint of a kind offers, sorted by name.
 *
 * Sorted so the order does not depend on how the server serialised the object. The
 * SMART-only flags are left out on an OAuth endpoint, where the API stores them as
 * false and refuses any attempt to turn one on.
 *
 * @param kind - The endpoint's kind.
 * @param capabilities - The flags as loaded.
 * @example
 * visibleCapabilities("oauth", { supportsEhrLaunch: false, allowsPublicClients: true });
 * // ["allowsPublicClients"]
 */
export function visibleCapabilities(
  kind: EndpointKind,
  capabilities: Readonly<Record<string, boolean>>,
): readonly string[] {
  return Object.keys(capabilities)
    .filter((name) => kind === "smart" || !SMART_ONLY.has(name))
    .toSorted();
}

/**
 * Labels a capability flag as an endpoint of a kind presents it.
 *
 * The one difference is `supportsBackendServices`. On a SMART endpoint that is SMART
 * Backend Services; on an OAuth endpoint the same flag is the plain
 * `client_credentials` grant, and calling it by the SMART name would mislead.
 *
 * @param name - The admin API's flag name.
 * @param kind - The endpoint's kind.
 * @example
 * capabilityLabelFor("supportsBackendServices", "oauth"); // "Client credentials"
 */
export function capabilityLabelFor(name: string, kind: EndpointKind): string {
  if (kind === "oauth" && name === "supportsBackendServices") {
    return "Client credentials";
  }
  return capabilityLabel(name);
}

/** What a new client asks for unless somebody changes it, per kind. */
const DEFAULT_CLIENT_SCOPES: Readonly<Record<EndpointKind, readonly string[]>> =
  {
    smart: ["openid", "fhirUser", "launch", "launch/patient", "patient/*.rs"],
    oauth: ["openid", "profile", "email"],
  };

/**
 * The scopes a client registration form starts with.
 *
 * @param kind - The endpoint's kind.
 * @example
 * defaultClientScopes("oauth"); // ["openid", "profile", "email"]
 */
export function defaultClientScopes(kind: EndpointKind): readonly string[] {
  return DEFAULT_CLIENT_SCOPES[kind];
}

/**
 * The presets an endpoint of a kind may start from.
 *
 * A SMART preset grants SMART-grammar scopes and launch context an OAuth endpoint
 * refuses, and the reverse, so each kind is offered only its own.
 *
 * @param kind - The endpoint's kind.
 * @param presets - Every preset the deployment ships.
 */
export function presetsFor(
  kind: EndpointKind,
  presets: readonly PresetView[],
): readonly PresetView[] {
  return presets.filter((preset) => preset.kind === kind);
}

/**
 * The hint under a rule's Description field.
 *
 * On an OAuth endpoint the consent screen phrases an API scope with the description
 * of the grant rule that granted it, so there the description is end-user copy and
 * the hint says so, lest an operator leave an internal note in it. Everywhere else
 * nobody but an operator reads it.
 *
 * @param kind - The endpoint's kind.
 * @param list - The list the rule belongs to.
 * @example
 * ruleDescriptionHint("oauth", "scopeGrants"); // "Shown to end users on the consent screen…"
 */
export function ruleDescriptionHint(
  kind: EndpointKind,
  list: RuleList,
): string {
  return kind === "oauth" && list === "scopeGrants"
    ? "Shown to end users on the consent screen as what this scope lets an app do. Write it for them, not as an internal note."
    : "Why this rule exists. The code view has no comments, so this is where the reasoning lives.";
}
