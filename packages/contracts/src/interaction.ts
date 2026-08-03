/**
 * The interaction state, described once.
 *
 * The three end-user pages render from this and the server's interaction API returns it,
 * so it is a wire contract rather than either side's internal shape — which makes this
 * package the right home for it. Both sides previously carried their own copy, and two
 * descriptions of one response is exactly the arrangement where a field is added to the
 * server and quietly ignored by the browser.
 *
 * A type rather than a Zod schema, unlike the rest of this package. Everything else here
 * describes a *request*, which is validated at the boundary; this describes a response,
 * and validating the server's own output in the browser would be ceremony — the browser
 * cannot do anything useful about a mismatch beyond what a type error at build time
 * already prevents.
 */

/** What the user must do next. */
export type InteractionStep =
  /** Authenticate: password, persona picker or upstream identity provider. */
  | "login"
  /** Choose the patient, or the encounter, the authorization is about. */
  | "select-context"
  /** Approve the scopes the app asked for. */
  | "consent"
  /** Nothing: the authorization is complete and a code has been issued. */
  | "complete"
  /** The user declined; the app is told `access_denied`. */
  | "denied";

/** A persona an end user may continue as, on a non-production endpoint. */
export interface InteractionPersona {
  readonly id: string;
  readonly displayName: string;
  readonly fhirUser: string | null;
}

/** Which launch context values this authorization requires. */
export interface InteractionRequirements {
  readonly patient: boolean;
  readonly encounter: boolean;
}

/** Everything a page needs to render a step. */
export interface InteractionView {
  readonly step: InteractionStep;
  readonly client: {
    readonly clientId: string;
    readonly name: string;
    readonly logoUrl: string | null;
  };
  readonly requestedScopes: readonly string[];
  readonly authMode: string;
  readonly allowsPersonas: boolean;
  readonly personas: readonly InteractionPersona[];
  readonly requirements: InteractionRequirements;
  /** Patients this user may act on, as bare FHIR ids. */
  readonly patients: readonly string[];
  readonly encounters: readonly string[];
  /** Whether an identifier outside the offered lists may be submitted. */
  readonly allowsFreeContextSelection: boolean;
  /**
   * The launch context resolved so far, or null when nothing has been.
   *
   * Typed loosely on purpose: this package does not depend on `@signet/core`'s
   * `LaunchContext` for a value the pages only read two fields of, and a structural type
   * keeps the contract readable on its own.
   */
  readonly resolvedContext: LaunchContextValues | null;
  /**
   * The upstream provider this endpoint federates to, when it federates at all.
   *
   * Present only in `oidc` auth mode. The name is what the sign-in button says, and
   * it is null when the operator did not give the provider one - the page then uses
   * neutral wording rather than showing an issuer URL, which means nothing to the
   * person reading it.
   */
  readonly federation?: { readonly name: string | null };
  /** Present when the step is `complete` or `denied`: where to send the browser. */
  readonly redirectTo?: string;
}

/**
 * The launch context as it appears in an interaction response.
 *
 * A record rather than the core type, so this package stays free of that dependency. The
 * keys are the launch context's: `patient`, `encounter`, `intent` and the rest.
 */
export type LaunchContextValues = Readonly<Record<string, unknown>>;
