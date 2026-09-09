// 3.0.0 (A4, audit): Vitest setup for
// the Svelte 5 + TypeScript
// frontend. Per audit: "Добавить
// Vitest + минимум 1 snapshot-тест на
// каждый из 9 роутов. Добавить
// Playwright e2e для критического
// флоу: login → sources add → plan
// → approve."
//
// Scope of this commit: Vitest
// setup + snapshot tests for the 3
// testable Svelte components
// (ListView, Placeholder, Nav).
// Playwright e2e is deferred —
// the Tauri app needs a real
// `agency-server` running for
// Playwright to hit, and that
// wiring is non-trivial (we'd
// need a test fixture that
// boots the binary on a random
// port and exposes the right env
// vars). The Vitest unit layer
// catches component-level bugs
// immediately; Playwright e2e
// is a 2.x → 3.x follow-up.

import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  plugins: [svelte({ hot: false })],
  // svelte 5 ships two
  // entry points: `index-client.js`
  // and `index-server.js`. The
  // package.json `exports` map
  // lists `default:
  // index-server.js`, which
  // Vite / Vitest pick in
  // Node-environment resolution
  // — that makes
  // `import { mount } from "svelte"`
  // fail with
  // `lifecycle_function_unavailable:
  // mount(...) is not available on
  // the server`. Forcing the
  // `browser` condition tells
  // Vite to pick the client entry
  // (which exports `mount`,
  // `flushSync`, `tick`, etc.)
  // even though the test env is
  // Node + jsdom.
  resolve: {
    conditions: ["browser"],
  },
  test: {
    environment: "jsdom",
    globals: false,
    // The Svelte compiler emits
    // `<svelte:options>` markers
    // that jsdom doesn't understand;
    // the `svelte` plugin strips
    // them. The svelte-check
    // `npm run check` script is
    // separate (CI runs both).
    include: ["src/**/*.test.ts", "src/**/*.test.svelte.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      // Cover the components
      // directory only; route
      // components are e2e-tested
      // (see Playwright follow-up).
      include: ["src/lib/components/**/*.svelte"],
    },
  },
});
