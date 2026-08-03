import { defineConfig } from "vitest/config";

/**
 * The web package's unit tests.
 *
 * `node` rather than `jsdom`, deliberately. Per the project's React guidelines every
 * piece of significant logic lives in a plain function — path building, error
 * parsing, formatting, form validation — and those are what is tested here.
 * Components are thin compositions of them, and are covered end to end by
 * Playwright instead, which exercises the real browser rather than a simulation of
 * one.
 */
export default defineConfig({
  test: {
    name: "web",
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
