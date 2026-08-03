import { describe, expect, it } from "vitest";

import { diffLines, diffSummary, withoutUnchangedRuns } from "./diff.js";

/** A compact rendering of a diff, for readable expectations. */
function rendered(before: string, after: string): string[] {
  const markers = { added: "+", removed: "-", kept: " " } as const;
  return diffLines(before, after).map(
    (line) => `${markers[line.change]}${line.text}`,
  );
}

describe("diffLines", () => {
  it("reports identical text as all kept", () => {
    const lines = diffLines("a\nb", "a\nb");
    expect(lines.every((line) => line.change === "kept")).toBe(true);
  });

  it("reports an insertion", () => {
    expect(rendered("a\nc", "a\nb\nc")).toEqual([" a", "+b", " c"]);
  });

  it("reports a deletion", () => {
    expect(rendered("a\nb\nc", "a\nc")).toEqual([" a", "-b", " c"]);
  });

  it("reports a change as a removal then an addition", () => {
    // "Was this, now that" reads better than the reverse, which is why the walk
    // prefers a removal where the table is indifferent.
    expect(rendered("a\nb\nc", "a\nB\nc")).toEqual([" a", "-b", "+B", " c"]);
  });

  it("carries line numbers from the side each line came from", () => {
    const lines = diffLines("a\nb", "a\nB");
    const removed = lines.find((line) => line.change === "removed");
    const added = lines.find((line) => line.change === "added");
    expect(removed?.before).toBe(2);
    expect(removed?.after).toBeUndefined();
    expect(added?.after).toBe(2);
    expect(added?.before).toBeUndefined();
  });

  it("handles an empty side", () => {
    expect(diffLines("", "a").some((line) => line.change === "added")).toBe(
      true,
    );
    expect(diffLines("a", "").some((line) => line.change === "removed")).toBe(
      true,
    );
  });

  it("finds the minimal change in a realistic document", () => {
    const before = ["{", '  "a": 1,', '  "b": 2,', '  "c": 3', "}"].join("\n");
    const after = ["{", '  "a": 1,', '  "b": 20,', '  "c": 3', "}"].join("\n");
    const summary = diffSummary(diffLines(before, after));
    expect(summary).toEqual({ added: 1, removed: 1 });
  });
});

describe("withoutUnchangedRuns", () => {
  it("elides a long run of unchanged lines", () => {
    const before = Array.from(
      { length: 30 },
      (_, index) => `line ${String(index)}`,
    );
    const after = [...before];
    after[15] = "changed";

    const abridged = withoutUnchangedRuns(
      diffLines(before.join("\n"), after.join("\n")),
    );
    expect(abridged.some((entry) => entry.change === "elided")).toBe(true);
    // Far fewer entries than the 31 lines the full diff has.
    expect(abridged.length).toBeLessThan(15);
  });

  it("keeps context either side of a change", () => {
    const lines = diffLines("a\nb\nc\nd\ne", "a\nb\nC\nd\ne");
    const abridged = withoutUnchangedRuns(lines, 1);
    const texts = abridged
      .filter((entry): entry is (typeof lines)[number] => "text" in entry)
      .map((entry) => entry.text);
    expect(texts).toContain("b");
    expect(texts).toContain("d");
  });

  it("keeps everything when everything changed", () => {
    const abridged = withoutUnchangedRuns(diffLines("a", "b"));
    expect(abridged.some((entry) => entry.change === "elided")).toBe(false);
  });
});

describe("diffSummary", () => {
  it("counts both sides", () => {
    expect(diffSummary(diffLines("a\nb", "a\nc\nd"))).toEqual({
      added: 2,
      removed: 1,
    });
  });
});
