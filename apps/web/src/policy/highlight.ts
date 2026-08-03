/**
 * Syntax highlighting for the code view, without a dependency.
 *
 * An editor library would bring a large bundle and an opinionated DOM for what this
 * needs: colouring JSON so a policy is scannable, and marking the line an error is on.
 * A tokeniser is a hundred lines and is testable, which the alternative is not.
 *
 * The textarea remains the thing being typed into — highlighted output is rendered
 * behind it, aligned by using the same font and metrics. That keeps every editing
 * behaviour the browser already has: selection, undo, spellcheck off, mobile keyboards,
 * and paste.
 */

/** What a token is, which decides how it is coloured. */
export type TokenKind =
  | "key"
  | "string"
  | "number"
  | "keyword"
  | "template"
  | "punctuation"
  | "plain";

/** One coloured run of text. */
export interface Token {
  readonly kind: TokenKind;
  readonly text: string;
}

/** JSON's literal keywords. */
const KEYWORDS = new Set(["true", "false", "null"]);

/** Reads a JSON string literal starting at `from`, including its quotes. */
function readString(text: string, from: number): string {
  let index = from + 1;
  while (index < text.length) {
    const character = text[index];
    if (character === "\\") {
      index += 2;
      continue;
    }
    index += 1;
    if (character === '"') {
      break;
    }
  }
  return text.slice(from, index);
}

/**
 * Which kind of token a string literal is.
 *
 * A literal followed by a colon is a key; one containing an interpolation is a
 * template, which is what a policy's interesting values are; anything else is an
 * ordinary string.
 *
 * @param text - The whole document.
 * @param literal - The literal, including its quotes.
 * @param after - The index just past the literal.
 */
function stringKind(text: string, literal: string, after: number): TokenKind {
  if (isKeyAt(text, after)) {
    return "key";
  }
  return literal.includes("{{") ? "template" : "string";
}

/** Whether a string literal is followed by a colon, making it a key. */
function isKeyAt(text: string, after: number): boolean {
  for (let index = after; index < text.length; index += 1) {
    const character = text[index];
    if (character === undefined || !/\s/.test(character)) {
      return character === ":";
    }
  }
  return false;
}

/**
 * Splits JSON into coloured tokens.
 *
 * Tolerant of invalid input: the code view highlights while the operator is midway
 * through typing, so anything unrecognised comes back as `plain` rather than throwing.
 * A string containing `{{ }}` is reported as `template`, because a policy's
 * interesting values are templates and seeing them stand out is the point.
 *
 * @param text - The editor's contents.
 */
export function tokenise(text: string): readonly Token[] {
  const tokens: Token[] = [];
  let plain = "";

  /** Flushes any accumulated uncoloured text. */
  const flush = () => {
    if (plain.length > 0) {
      tokens.push({ kind: "plain", text: plain });
      plain = "";
    }
  };

  let index = 0;
  while (index < text.length) {
    const character = text[index] ?? "";

    if (character === '"') {
      const literal = readString(text, index);
      flush();
      const after = index + literal.length;
      tokens.push({ kind: stringKind(text, literal, after), text: literal });
      index = after;
      continue;
    }

    if (/[-\d]/.test(character) && /[\s:[,]/.test(text[index - 1] ?? " ")) {
      const match = /^-?\d+(?:\.\d+)?(?:[Ee][+-]?\d+)?/.exec(text.slice(index));
      if (match !== null) {
        flush();
        tokens.push({ kind: "number", text: match[0] });
        index += match[0].length;
        continue;
      }
    }

    if (/[a-z]/.test(character)) {
      const match = /^[a-z]+/.exec(text.slice(index));
      if (match !== null && KEYWORDS.has(match[0])) {
        flush();
        tokens.push({ kind: "keyword", text: match[0] });
        index += match[0].length;
        continue;
      }
    }

    if ("{}[],:".includes(character)) {
      flush();
      tokens.push({ kind: "punctuation", text: character });
      index += 1;
      continue;
    }

    plain += character;
    index += 1;
  }

  flush();
  return tokens;
}

/**
 * The line a dotted document path is on.
 *
 * Used to point at the line an issue concerns. Approximate by design: it walks the text
 * looking for each path segment as a key in order, which is right for a document the
 * editor itself formatted — one key per line — and gives up rather than guessing when
 * the text has been reflowed.
 *
 * @param text - The editor's contents.
 * @param path - A dotted path, as `parsePolicy` reports.
 * @returns The one-based line number, or undefined when it cannot be located.
 */
export function lineForPath(text: string, path: string): number | undefined {
  if (path === "") {
    return undefined;
  }

  const lines = text.split("\n");
  let line = 0;
  for (const segment of path.split(".")) {
    // Numeric segments are array indices, which have no key to find; the line stays
    // where the containing key was.
    if (/^\d+$/.test(segment)) {
      continue;
    }
    const needle = `"${segment}"`;
    const found = lines.findIndex(
      (candidate, index) => index >= line && candidate.includes(needle),
    );
    if (found === -1) {
      return line === 0 ? undefined : line + 1;
    }
    line = found;
  }
  return line + 1;
}
