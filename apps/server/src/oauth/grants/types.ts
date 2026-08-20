/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The contract every grant handler satisfies.
 *
 * A grant establishes two things and nothing else: who the token is for, and what
 * was authorised. It then calls `issueTokens`, which is the only place a policy is
 * consulted or a signature produced. Keeping the handlers to that shape is what
 * makes it possible to say, of all three grants, that they cannot disagree about
 * which policy governs a token.
 *
 * Author: John Grimes
 */

import type { ResolvedIssuerContext } from "../../context.js";
import type { TokenErrorCode } from "../../http/oauthErrors.js";
import type { RequestMetadata } from "../../http/requestMeta.js";
import type { AuthenticatedClient } from "../clientAuthentication.js";
import type { TokenResponse } from "@signet/core";

/**
 * A parsed form body.
 *
 * Typed as `unknown` values rather than as Hono's own union, so that this module
 * needs no dependency on the framework and so that a body assembled by a test is
 * assignable. Every read narrows to `string` anyway - see {@link formField}.
 */
export type FormBody = Readonly<Record<string, unknown>>;

/** What the token endpoint hands a grant handler. */
export interface GrantRequest {
  readonly issuerContext: ResolvedIssuerContext;
  readonly authenticated: AuthenticatedClient;
  readonly body: FormBody;
  readonly metadata: RequestMetadata;
}

/** A grant that produced a token, or the refusal to be audited and returned. */
export type GrantOutcome =
  | { readonly ok: true; readonly response: TokenResponse }
  | {
      readonly ok: false;
      readonly code: TokenErrorCode;
      readonly description: string;
      /** Extra fields for the `token.denied` audit event. */
      readonly detail?: Record<string, unknown>;
      /**
       * Overrides the status RFC 6749 §5.2 would imply.
       *
       * Only for a refusal that is the deployment's fault rather than the
       * client's - see `./issuanceRefusals.ts`. A 400 there would send an app
       * developer looking for a bug they do not have.
       */
      readonly status?: 500;
    };

/**
 * Reads a single-valued form field.
 *
 * A repeated field arrives as an array and a file upload as a `File`; both are
 * treated as absent. A repeated OAuth parameter is a malformed request rather than
 * a list, and returning "absent" means it is refused for the missing parameter
 * instead of the server having to choose which of two values the caller meant.
 */
export function formField(body: FormBody, name: string): string | undefined {
  const value = body[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/** Builds a refusal. */
export function grantRefusal(
  code: TokenErrorCode,
  description: string,
  detail?: Record<string, unknown>,
  status?: 500,
): GrantOutcome {
  return {
    ok: false,
    code,
    description,
    ...(detail === undefined ? {} : { detail }),
    ...(status === undefined ? {} : { status }),
  };
}
