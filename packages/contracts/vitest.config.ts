import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "contracts",
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
