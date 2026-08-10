/**
 * The seed script's refusal of a port variable that came from a `.env` file.
 *
 * An integration test rather than a unit test, and deliberately: the guard lives in
 * `scripts/seedStack.mjs`, which runs as bare `node` inside the runtime image and so
 * can import nothing, and which performs I/O at the top level and so cannot be
 * imported by a test either. Running it is the only way to assert it.
 *
 * Each case gets its own directory, because the thing under test is what Bun loads
 * from the working directory.
 *
 * Author: John Grimes
 */

import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const SEED = path.join(import.meta.dir, "..", "..", "scripts", "seedStack.mjs");

/** Part of the refusal, distinctive enough that nothing else prints it. */
const REFUSAL = "where it does nothing";

/** What a run of the seed reported. */
interface Run {
  status: number | null;
  output: string;
}

/**
 * Runs the seed in a fresh directory the caller has laid out.
 *
 * `SIGNET_BASE_URL` points at a port nothing listens on, so a run that gets past
 * the guard fails on its first request rather than reaching a server that happens
 * to be up on this machine.
 *
 * @param prepare - populates the directory before the seed runs.
 * @returns the exit status and the output.
 */
function seedWith(prepare: (cwd: string) => void): Run {
  const cwd = mkdtempSync(path.join(tmpdir(), "signet-seed-"));
  prepare(cwd);
  const env = { ...process.env, SIGNET_BASE_URL: "http://127.0.0.1:1" };
  // The child is a `bun run` of its own, not a test run; NODE_ENV=test would
  // change which files Bun loads.
  delete env["NODE_ENV"];
  const result = spawnSync("bun", [SEED], { cwd, env, encoding: "utf8" });
  return {
    status: result.status,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
  };
}

/**
 * Runs the seed in a directory holding the given files.
 *
 * @param files - the files to write, by name.
 * @returns the exit status and the output.
 */
function seedIn(files: Record<string, string>): Run {
  return seedWith((cwd) => {
    for (const [name, contents] of Object.entries(files)) {
      writeFileSync(path.join(cwd, name), contents);
    }
  });
}

describe("the seed script's env-file port guard", () => {
  // The bug this exists for. Bun loads `.env.local` into the seed but not into
  // `docker compose`, so a port declared there moves the URLs the seed *stores*
  // and not the ones the stack *serves* - the endpoint ends up pointing at a
  // Pathling nobody published.
  test("refuses a port declared in .env.local", () => {
    const { status, output } = seedIn({ ".env.local": "SIGNET_PORT=3100\n" });
    expect(status).not.toBe(0);
    expect(output).toContain("SIGNET_PORT");
    expect(output).toContain(REFUSAL);
    // The refusal has to say what to do instead, not only that it refused.
    expect(output).toContain("export SIGNET_PORT=");
  });

  // `.envrc` is direnv's file, which the README recommends. It begins with `.env`
  // but is not one of Bun's: direnv exports what it declares into the shell, so
  // compose, Playwright and the seed all see it. Refusing it would refuse the
  // documented workflow, and would make the end-to-end suite unrunnable for
  // anybody using direnv - the global setup spawns this script.
  test("allows a port exported by direnv from .envrc", () => {
    const { output } = seedIn({
      ".envrc": "export SIGNET_PORT=3100 PATHLING_PORT=8180 APP_PORT=4100\n",
    });
    expect(output).not.toContain(REFUSAL);
  });

  // Every `.env` file Bun might load, not just `.env.local`.
  test("refuses a port declared in .env", () => {
    const { status, output } = seedIn({ ".env": "PATHLING_PORT=8180\n" });
    expect(status).not.toBe(0);
    expect(output).toContain("PATHLING_PORT");
  });

  // `export FOO=bar` is valid in a `.env` file Bun reads, and is the shape a
  // developer who half-followed the documentation would write.
  test("refuses a port declared with an export keyword", () => {
    const { status, output } = seedIn({
      ".env.local": "export APP_PORT=4100\n",
    });
    expect(status).not.toBe(0);
    expect(output).toContain("APP_PORT");
  });

  // The repository's own `.env.example` documents these variables, and is a file
  // Bun never loads. Refusing on it would refuse in a fresh checkout.
  test("ignores .env.example", () => {
    const { output } = seedIn({ ".env.example": "SIGNET_PORT=3000\n" });
    expect(output).not.toContain(REFUSAL);
  });

  // A commented line is documentation, which is exactly what the shipped example
  // files carry.
  test("ignores a commented port", () => {
    const { output } = seedIn({ ".env.local": "# SIGNET_PORT=3100\n" });
    expect(output).not.toContain(REFUSAL);
  });

  // A directory whose name happens to fit the pattern would make a read of it
  // throw EISDIR, which would fail the seed for a reason that has nothing to do
  // with ports.
  test("ignores a directory named like an env file", () => {
    const { output } = seedWith((cwd) => {
      mkdirSync(path.join(cwd, ".env.d"));
    });
    expect(output).not.toContain("EISDIR");
  });

  // Bun follows a symlinked `.env.local` and loads what it points at, so the guard
  // has to look through one too. Skipping everything that is not a regular file
  // would let exactly this arrangement past.
  test("refuses a port behind a symlinked env file", () => {
    const { status, output } = seedWith((cwd) => {
      writeFileSync(path.join(cwd, "ports.env"), "SIGNET_PORT=3100\n");
      symlinkSync(path.join(cwd, "ports.env"), path.join(cwd, ".env.local"));
    });
    expect(status).not.toBe(0);
    expect(output).toContain(REFUSAL);
  });

  // A symlink pointing at nothing is not a reason to fail the seed.
  test("ignores a broken symlink", () => {
    const { output } = seedWith((cwd) => {
      symlinkSync(path.join(cwd, "gone.env"), path.join(cwd, ".env.local"));
    });
    expect(output).not.toContain(REFUSAL);
    expect(output).not.toContain("ENOENT");
  });

  // The guard is about three variables and must not obstruct anything else a
  // developer keeps in the file.
  test("allows an unrelated variable", () => {
    const { output } = seedIn({
      ".env.local": "SIGNET_SEED_TENANT=demo\n",
    });
    expect(output).not.toContain(REFUSAL);
  });
});
