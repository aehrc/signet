import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["packages/*", "apps/server", "apps/web"],
    // Migrations run once, here, before any worker starts. Applying them from
    // whichever integration file ran first meant DDL taking exclusive table locks
    // while another worker held row locks on the same tables, which Postgres
    // resolves by killing one of them — see `packages/db/src/test/schemaReady.ts`.
    globalSetup: ["./packages/db/src/test/globalSetup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["packages/*/src/**", "apps/server/src/**"],
      exclude: [
        "**/node_modules/**",
        "**/dist/**",
        "**/*.test.{ts,tsx}",
        "**/*.stories.{ts,tsx}",
        "**/test/**",
        "**/index.ts",
      ],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
});
