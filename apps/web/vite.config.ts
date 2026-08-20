/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * The end-user pages served under an endpoint's issuer, exactly as the server's
 * static handler recognises them. Everything else under `/t/` is an OAuth or
 * portal API route and must reach the server; these five paths are pages this
 * dev server renders itself. Canonical list:
 * `apps/server/src/oauth/endUserPages.ts`.
 */
const END_USER_PAGE_PATTERN =
  /^\/t\/[^/]+\/e\/[^/]+\/(login|picker|consent|manage|apps)$/;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:3000", changeOrigin: true },
      "/t": {
        target: "http://localhost:3000",
        changeOrigin: true,
        bypass: (req) =>
          END_USER_PAGE_PATTERN.test(req.url?.split("?", 1)[0] ?? "")
            ? "/index.html"
            : undefined,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
