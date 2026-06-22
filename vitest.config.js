import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/bundle/**/*.test.js"],
    exclude: ["examples/**", "tests/e2e/**", "node_modules/**"],
  },
});
