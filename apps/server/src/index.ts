import { serve } from "@hono/node-server";

import { createApp } from "./app.js";
import { ConfigError, loadConfig } from "./config.js";

let config;
try {
  config = loadConfig(process.env);
} catch (error) {
  if (error instanceof ConfigError) {
    // Fail loudly and specifically rather than starting up half-configured.
    console.error(`Signet configuration error: ${error.message}`);
    process.exit(1);
  }
  throw error;
}

const app = createApp();

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`Signet listening on http://localhost:${String(info.port)}`);
});
