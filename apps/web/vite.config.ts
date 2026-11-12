/*
 * Copyright © 2026, Commonwealth Scientific and Industrial Research Organisation
 * (CSIRO) ABN 41 687 119 230. Licensed under the Apache License, Version 2.0.
 */

/**
 * Author: John Grimes
 */

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

/**
 * The end-user pages served under an endpoint's issuer, exactly as the server's
 * static handler recognises them. Everything else under `/t/` is an OAuth or
 * portal API route and must reach the server; these six paths are pages this
 * dev server renders itself. Canonical list:
 * `apps/server/src/oauth/endUserPages.ts`.
 */
const END_USER_PAGE_PATTERN =
  /^\/t\/[^/]+\/e\/[^/]+\/(login|picker|consent|manage|apps|invitation)$/;

export default defineConfig(({ mode }) => {
  // The Signet server the dev server proxies to. Read from `.env.local` in this
  // directory; see `.env.example`.
  const serverUrl =
    loadEnv(mode, import.meta.dirname, "SIGNET_").SIGNET_SERVER_URL ??
    "http://localhost:3000";

  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: {
        "/api": { target: serverUrl, changeOrigin: true },
        "/t": {
          target: serverUrl,
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
  };
});
