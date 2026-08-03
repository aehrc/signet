/**
 * The policy document as the editor holds it.
 *
 * One document, two projections. The builder edits it structurally; code mode edits
 * text that parses back to it. Both go through here, which is what makes "switching
 * modes round-trips losslessly" a property of one function pair rather than a claim.
 *
 * Validation is not reimplemented. `@signet/contracts`'s schema delegates to
 * `@signet/core`'s validator — the same one the admin API uses — so a document the
 * editor accepts is one the server will accept, and a document it refuses is refused
 * for the same reason and at the same path.
 *
 * The serialisation is JSON rather than YAML, and that is a deliberate narrowing of
 * the original design. The point of YAML in an editor is comments, and comments cannot
 * survive a structural edit in the builder: the moment a rule is dragged, any comment
 * attached to it either moves wrongly or disappears. Round-tripping losslessly matters
 * more than commenting, so the code mode is JSON — the form the document takes in the
 * database and over the API — and the builder's rule descriptions carry the prose that
 * comments would have.
 */

import { policyDocumentSchema } from "@signet/contracts";

import type { PolicyDocument } from "@signet/core";

/** A problem with the text, addressed by path where there is one. */
export interface DocumentIssue {
  /** Dotted path into the document, or empty for the document as a whole. */
  readonly path: string;
  readonly message: string;
}

/** The outcome of parsing what the operator typed. */
export type DocumentParse =
  | { readonly ok: true; readonly document: PolicyDocument }
  | { readonly ok: false; readonly issues: readonly DocumentIssue[] };

/** Indentation for the code editor. Two spaces, as the rest of the project uses. */
const INDENT = 2;

/**
 * Renders a document as the text the code editor shows.
 *
 * Stable: the same document always produces the same text, because the key order is
 * whatever the document carries and no field is reordered on the way out. That is
 * what lets a diff between two versions mean something.
 *
 * @param document - The document to render.
 */
export function formatPolicy(document: PolicyDocument): string {
  return `${JSON.stringify(document, undefined, INDENT)}\n`;
}

/**
 * Parses the code editor's text into a document.
 *
 * Syntax errors and validation failures are reported the same way, because to the
 * person typing they are the same kind of problem — something about this text is
 * wrong, and here is where.
 *
 * @param text - The editor's contents.
 */
export function parsePolicy(text: string): DocumentParse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return {
      ok: false,
      issues: [
        {
          path: "",
          message:
            error instanceof Error ? error.message : "That is not valid JSON",
        },
      ],
    };
  }

  const result = policyDocumentSchema.safeParse(parsed);
  if (!result.success) {
    return {
      ok: false,
      issues: result.error.issues.map((issue) => ({
        path: issue.path.map(String).join("."),
        message: issue.message,
      })),
    };
  }
  return { ok: true, document: result.data };
}

/**
 * Whether two documents differ.
 *
 * Compared by their serialised form rather than field by field, because that is the
 * comparison that decides whether there is anything to save — and it cannot fall
 * behind a field added to the document type.
 *
 * @param a - One document.
 * @param b - The other.
 */
export function policiesDiffer(a: PolicyDocument, b: PolicyDocument): boolean {
  return formatPolicy(a) !== formatPolicy(b);
}
