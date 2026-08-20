/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * The code view: the document as text, highlighted, with its errors in place.
 *
 * A textarea with the highlighted text rendered behind it, rather than a
 * contenteditable or an editor library. That keeps every behaviour the browser already
 * has - selection, undo, paste, a sane mobile keyboard - and costs one alignment
 * constraint: the two layers must use the same font, size and whitespace handling, which
 * is why both carry the same typography classes.
 *
 * Validation runs on every change and is shown rather than enforced: an operator midway
 * through typing a rule has invalid text, and refusing to let them continue would be
 * absurd. The Save button is what the invalid state disables.
 *
 * Author: John Grimes
 */

import { useMemo } from "react";

import { lineForPath, tokenise } from "./highlight.js";

import type { DocumentIssue } from "./document.js";
import type { TokenKind } from "./highlight.js";

/** Tailwind classes for each token kind, all from theme tokens. */
const TOKEN_CLASSES: Readonly<Record<TokenKind, string>> = {
  key: "text-primary",
  string: "text-success",
  template: "text-warning font-semibold",
  number: "text-info",
  keyword: "text-secondary",
  punctuation: "text-base-content/50",
  plain: "",
};

/**
 * Typography both layers must share, or the highlighting drifts from the text.
 *
 * `max-sm:text-base` is on both for the same reason it is on every other control:
 * a mobile browser zooms into a focused field whose text is under 16px and does
 * not zoom back out. The line height is fixed at `leading-5` either way, so the
 * two layers still agree line for line at the larger size.
 */
const EDITOR_TYPOGRAPHY =
  "font-mono text-xs max-sm:text-base leading-5 whitespace-pre-wrap break-words p-3";

interface CodeEditorProps {
  readonly value: string;
  readonly onChange: (value: string) => void;
  readonly issues: readonly DocumentIssue[];
  readonly rows?: number;
  readonly disabled?: boolean;
}

/** The document as editable, highlighted text. */
export function CodeEditor({
  value,
  onChange,
  issues,
  rows = 28,
  disabled,
}: Readonly<CodeEditorProps>) {
  const tokens = useMemo(() => tokenise(value), [value]);

  return (
    <div>
      <div className="border-base-300 rounded-box relative overflow-hidden border">
        <pre
          aria-hidden="true"
          className={`bg-base-200 m-0 overflow-hidden ${EDITOR_TYPOGRAPHY}`}
          style={{ minHeight: `${String(rows * 1.25)}rem` }}
        >
          {tokens.map((token, index) => (
            <span
              // Position is the identity here: tokens have no other, and the list is
              // rebuilt wholesale on every keystroke.
              key={`${String(index)}-${token.kind}`}
              className={TOKEN_CLASSES[token.kind]}
            >
              {token.text}
            </span>
          ))}
        </pre>
        <textarea
          className={`absolute inset-0 h-full w-full resize-none bg-transparent text-transparent caret-current outline-none ${EDITOR_TYPOGRAPHY}`}
          aria-label="Policy document"
          spellCheck={false}
          value={value}
          disabled={disabled}
          onChange={(event) => {
            onChange(event.currentTarget.value);
          }}
        />
      </div>

      {issues.length === 0 ? null : (
        <ul className="mt-3 flex flex-col gap-1" aria-label="Policy problems">
          {issues.map((issue) => {
            const line = lineForPath(value, issue.path);
            return (
              <li
                key={`${issue.path}-${issue.message}`}
                className="text-error text-xs max-sm:text-base"
              >
                <code className="font-mono">
                  {issue.path === "" ? "document" : issue.path}
                  {line === undefined ? "" : ` (line ${String(line)})`}
                </code>{" "}
                {issue.message}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
