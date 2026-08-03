/**
 * The diff shown before a policy is saved.
 *
 * Publishing a policy changes what every token from this endpoint carries, so the save
 * step shows what is actually changing rather than asking for confirmation of a number.
 * A line diff over the formatted documents is the right granularity: the document is one
 * key per line, so a changed rule reads as a changed line.
 *
 * The algorithm is a longest-common-subsequence walk, which is small, pure and exact.
 * A heuristic diff would occasionally attribute a change to the wrong line, and this is
 * read to decide whether to publish.
 */

/** What happened to one line. */
export type LineChange = "kept" | "added" | "removed";

/** One line of a diff. */
export interface DiffLine {
  readonly change: LineChange;
  readonly text: string;
  /** Line number in the previous version, where it had one. */
  readonly before?: number;
  /** Line number in the next version, where it has one. */
  readonly after?: number;
}

/**
 * Longest common subsequence lengths for two line arrays.
 *
 * A full table rather than a windowed one: a policy document is tens of lines, so the
 * quadratic space is a few thousand numbers and the exactness is worth more than the
 * saving.
 */
function lcsTable(
  before: readonly string[],
  after: readonly string[],
): readonly (readonly number[])[] {
  const table: number[][] = Array.from({ length: before.length + 1 }, () =>
    Array.from({ length: after.length + 1 }, (): number => 0),
  );

  for (let i = before.length - 1; i >= 0; i -= 1) {
    for (let j = after.length - 1; j >= 0; j -= 1) {
      const row = table[i];
      const nextRow = table[i + 1];
      if (row === undefined || nextRow === undefined) {
        continue;
      }
      row[j] =
        before[i] === after[j]
          ? (nextRow[j + 1] ?? 0) + 1
          : Math.max(nextRow[j] ?? 0, row[j + 1] ?? 0);
    }
  }
  return table;
}

/**
 * Diffs two documents, line by line.
 *
 * @param before - The version currently published, formatted.
 * @param after - The version about to be saved, formatted.
 */
export function diffLines(before: string, after: string): readonly DiffLine[] {
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  const table = lcsTable(beforeLines, afterLines);

  const lines: DiffLine[] = [];
  let i = 0;
  let j = 0;

  while (i < beforeLines.length && j < afterLines.length) {
    if (beforeLines[i] === afterLines[j]) {
      lines.push({
        change: "kept",
        text: beforeLines[i] ?? "",
        before: i + 1,
        after: j + 1,
      });
      i += 1;
      j += 1;
      continue;
    }
    // Removals before additions where the table is indifferent, so a changed line
    // reads as "was this, now that" rather than the other way round.
    if ((table[i + 1]?.[j] ?? 0) >= (table[i]?.[j + 1] ?? 0)) {
      lines.push({
        change: "removed",
        text: beforeLines[i] ?? "",
        before: i + 1,
      });
      i += 1;
    } else {
      lines.push({ change: "added", text: afterLines[j] ?? "", after: j + 1 });
      j += 1;
    }
  }

  for (; i < beforeLines.length; i += 1) {
    lines.push({
      change: "removed",
      text: beforeLines[i] ?? "",
      before: i + 1,
    });
  }
  for (; j < afterLines.length; j += 1) {
    lines.push({ change: "added", text: afterLines[j] ?? "", after: j + 1 });
  }

  return lines;
}

/**
 * Drops runs of unchanged lines, keeping a little context around each change.
 *
 * A policy document is long enough that an unabridged diff buries three changed lines
 * in ninety identical ones.
 *
 * @param lines - The full diff.
 * @param context - How many unchanged lines to keep either side of a change.
 */
export function withoutUnchangedRuns(
  lines: readonly DiffLine[],
  context = 2,
): readonly (
  DiffLine | { readonly change: "elided"; readonly count: number }
)[] {
  const interesting = new Set<number>();
  for (const [index, line] of lines.entries()) {
    if (line.change === "kept") {
      continue;
    }
    for (
      let nearby = Math.max(0, index - context);
      nearby <= Math.min(lines.length - 1, index + context);
      nearby += 1
    ) {
      interesting.add(nearby);
    }
  }

  const result: (DiffLine | { change: "elided"; count: number })[] = [];
  let elided = 0;
  for (const [index, line] of lines.entries()) {
    if (interesting.has(index)) {
      if (elided > 0) {
        result.push({ change: "elided", count: elided });
        elided = 0;
      }
      result.push(line);
    } else {
      elided += 1;
    }
  }
  if (elided > 0) {
    result.push({ change: "elided", count: elided });
  }
  return result;
}

/** How many lines a diff adds and removes, for the summary line. */
export function diffSummary(lines: readonly DiffLine[]): {
  readonly added: number;
  readonly removed: number;
} {
  return {
    added: lines.filter((line) => line.change === "added").length,
    removed: lines.filter((line) => line.change === "removed").length,
  };
}
