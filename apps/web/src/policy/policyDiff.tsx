/**
 * The diff shown before saving.
 *
 * Rendered from `./diff.js`, which does the work. Long runs of unchanged lines are
 * elided, because a policy document is long enough that three changed lines otherwise
 * arrive buried in ninety identical ones.
 *
 * Colour is not the only signal: each line carries `+` or `-`, so the diff is readable
 * without relying on the reader distinguishing red from green.
 *
 * Author: John Grimes
 */

import { diffLines, diffSummary, withoutUnchangedRuns } from "./diff.js";
import { countOf } from "../formatting/values.js";

interface PolicyDiffProps {
  /** The version currently published, formatted. */
  readonly before: string;
  /** The version about to be saved, formatted. */
  readonly after: string;
}

/** Tailwind classes per change kind, from theme tokens. */
const CHANGE_CLASSES = {
  added: "bg-success/10 text-success",
  removed: "bg-error/10 text-error",
  kept: "text-base-content/70",
} as const;

/** The change marker, so colour is not carrying the meaning alone. */
const MARKERS = { added: "+", removed: "-", kept: " " } as const;

/** A line diff between two policy documents. */
export function PolicyDiff({ before, after }: Readonly<PolicyDiffProps>) {
  const lines = diffLines(before, after);
  const summary = diffSummary(lines);
  const abridged = withoutUnchangedRuns(lines);

  return (
    <div>
      <p className="text-base-content/70 mb-2 text-sm max-sm:text-base">
        {countOf(summary.added, "line")} added,{" "}
        {countOf(summary.removed, "line")} removed, against the published
        version.
      </p>
      <pre className="border-base-300 rounded-box max-h-80 overflow-auto border font-mono text-xs">
        {abridged.map((entry, index) =>
          entry.change === "elided" ? (
            <div
              key={`elided-${String(index)}`}
              className="bg-base-200 text-base-content/50 px-3 py-1"
            >
              … {countOf(entry.count, "unchanged line")}
            </div>
          ) : (
            <div
              key={`${String(entry.before ?? 0)}-${String(entry.after ?? 0)}-${String(index)}`}
              className={`px-3 ${CHANGE_CLASSES[entry.change]}`}
            >
              <span aria-hidden="true">{MARKERS[entry.change]}</span>
              {entry.text}
            </div>
          ),
        )}
      </pre>
    </div>
  );
}
