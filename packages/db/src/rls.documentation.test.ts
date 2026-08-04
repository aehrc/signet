/**
 * What the repository says about who the policies constrain.
 *
 * Four documents used to say that the policies leave the Signet process
 * unconstrained, and they were right: Signet connected as the owner of its tables,
 * and Postgres exempts a table's owner from its policies. Each of them said so
 * plainly rather than hiding it, which was the honest thing to do at the time and
 * is exactly what makes them dangerous now - a reader who trusts the documentation
 * would conclude the guarantee does not exist.
 *
 * The cheapest way to break a promise is to change the implementation underneath a
 * document that still advertises the old behaviour, so this is a test rather than a
 * grep somebody ran once. It works in the direction that survives rewording: each
 * document must *state the current posture*, in its own words but recognisably. A
 * negative check for retired phrasings would pass the moment somebody reintroduced
 * the old claim in different words, and the positive one cannot.
 *
 * Author: John Grimes
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/** The repository root, from this file's location within it. */
const repositoryRoot = fileURLToPath(new URL("../../..", import.meta.url));

/**
 * The documents FR-024 names, and what each must now say.
 *
 * One phrase per document, chosen to be the thing that could only be written by
 * somebody describing the current arrangement: a non-owning role, and a `migrate`
 * that needs the owner. A document reverted to the old claim fails, because the old
 * claim cannot contain either.
 */
const DOCUMENTS: readonly {
  readonly file: string;
  readonly states: readonly RegExp[];
}[] = [
  {
    file: "CLAUDE.md",
    states: [/non-owning/i, /serving role/i],
  },
  {
    file: "docs/operations.md",
    states: [
      /serving role/i,
      /SIGNET_DATABASE_OWNER_URL/,
      /must be non-owning/i,
    ],
  },
  {
    file: "packages/db/src/rls.ts",
    states: [
      /owns none of these tables|owns none of its tables/i,
      /serving role/i,
    ],
  },
  {
    file: "deploy/compose/docker-compose.yml",
    states: [/signet_app/, /non-owning/i],
  },
];

/**
 * Claims no document may make any more, as word sequences.
 *
 * Written as words rather than as sentences because the first attempt at this was
 * defeated by markdown: the retired sentence reads "what this does **not** do", and
 * a pattern matching "does not do" does not match it. Words are joined by
 * {@link claim} with a separator that skips emphasis, punctuation and line breaks,
 * so a reverted paragraph fails here whether or not it is styled the way it was.
 *
 * Deliberately few. A phrase list cannot enumerate the ways of saying "the policies
 * do not apply to us", which is why the positive assertions above carry the weight;
 * these catch a revert of the exact paragraphs that were removed.
 */
const RETIRED_CLAIMS: readonly RegExp[] = [
  claim("does", "not", "do", "is", "constrain", "the", "Signet", "process"),
  claim("Signet", "connects", "as", "the", "owner"),
  claim("the", "policies", "do", "not", "constrain", "Signet"),
  claim("Signet", "connects", "as", "the", "table", "owner"),
];

/**
 * A sequence of words, however it is punctuated or wrapped between them.
 *
 * The separator permits up to a few non-word characters - `**`, `_`, a newline and
 * the indentation after it - which is what a sentence broken across lines or
 * emphasised mid-clause looks like. It deliberately does not permit another word,
 * so the pattern still describes one claim rather than any text containing those
 * words somewhere.
 */
function claim(...words: readonly string[]): RegExp {
  return new RegExp(words.join(String.raw`[^\w]{1,8}`), "i");
}

/** A document's contents, from the repository root. */
function contentsOf(file: string): string {
  return readFileSync(path.join(repositoryRoot, file), "utf8");
}

describe("what the repository claims about tenant isolation", () => {
  it.each(DOCUMENTS)("finds $file", ({ file }) => {
    // Guards the guard: a root that resolved wrongly would throw here rather than
    // silently making every assertion below vacuous.
    expect(contentsOf(file).length).toBeGreaterThan(100);
  });

  it.each(DOCUMENTS)("$file states the current posture", ({ file, states }) => {
    const source = contentsOf(file);
    for (const pattern of states) {
      expect(source, `${file} does not state ${String(pattern)}`).toMatch(
        pattern,
      );
    }
  });

  it.each(DOCUMENTS)("$file makes no retired claim", ({ file }) => {
    const source = contentsOf(file);
    for (const pattern of RETIRED_CLAIMS) {
      expect(source, `${file} still claims ${String(pattern)}`).not.toMatch(
        pattern,
      );
    }
  });
});
