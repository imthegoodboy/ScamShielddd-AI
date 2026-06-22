import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  timeout: 45_000,
  expect: { timeout: 8_000 },
  use: {
    baseURL: "http://127.0.0.1:5194",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "npx http-server bundle -p 5194 -a 127.0.0.1 --silent",
    url: "http://127.0.0.1:5194",
    reuseExistingServer: !process.env.CI,
    timeout: 20_000,
  },
});
