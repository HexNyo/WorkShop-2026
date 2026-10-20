import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  // Traces et vidéos dans le conteneur ; seules les captures sont écrites sur le montage.
  outputDir: "/tmp/playwright-results",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.UI_BASE_URL ?? "http://localhost:8080",
    viewport: { width: 1440, height: 1000 },
    locale: "fr-FR",
    timezoneId: "Europe/Paris",
    screenshot: "off",
    trace: "off",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } }],
});
