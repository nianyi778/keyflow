import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Worker test setup. Tests run inside the workerd runtime via
// @cloudflare/vitest-pool-workers, so they exercise the real D1 / KV bindings.
//
// We deliberately do NOT load wrangler.jsonc here: the `assets` and
// `ratelimits` entries in that config are not modelled by the test pool, and
// loading it would fail. Instead we declare a minimal set of bindings
// (D1 + KV + the secrets the worker reads) directly via miniflare options.
export default defineConfig({
  plugins: [
    cloudflareTest({
      main: "./src/index.ts",
      miniflare: {
        compatibilityDate: "2025-01-01",
        compatibilityFlags: ["nodejs_compat"],
        d1Databases: { DB: "test-db" },
        kvNamespaces: ["KV"],
        bindings: {
          JWT_SECRET: "test-jwt-secret-do-not-use-in-prod",
          GOOGLE_CLIENT_ID: "test-google-client-id",
          GOOGLE_CLIENT_SECRET: "test-google-client-secret",
        },
      },
    }),
  ],
});
