import { defineConfig } from "@playwright/test";

const expectedBaseUrl = "http://pentest-web:8000";
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? expectedBaseUrl;
if (baseURL !== expectedBaseUrl) {
  throw new Error(`Browser tests are restricted to ${expectedBaseUrl}.`);
}

const authenticationState = "/tmp/browser-auth/alex.json";
const authenticatedUse = {
  baseURL,
  storageState: authenticationState,
};
const lifecycleSpec = /session-lifecycle\.spec\.mjs/;

export default defineConfig({
  testDir: "./browser-tests",
  testMatch: /.*\.spec\.mjs/,
  forbidOnly: true,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 7_500 },
  reporter: [["line"]],
  outputDir: "/tmp/playwright-results",
  use: {
    baseURL,
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    {
      name: "auth-setup",
      testMatch: /auth\.setup\.mjs/,
      use: { baseURL, browserName: "chromium", storageState: undefined },
    },
    {
      name: "chromium-desktop",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "chromium",
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "firefox-desktop",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "firefox",
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "webkit-desktop",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "webkit",
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "chromium-phone",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "chromium",
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 2,
        hasTouch: true,
        isMobile: true,
      },
    },
    {
      name: "firefox-narrow",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "firefox",
        viewport: { width: 390, height: 844 },
      },
    },
    {
      name: "webkit-iphone",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "webkit",
        viewport: { width: 390, height: 844 },
        deviceScaleFactor: 3,
        hasTouch: true,
        isMobile: true,
      },
    },
    {
      name: "webkit-ipad",
      dependencies: ["auth-setup"],
      testIgnore: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "webkit",
        viewport: { width: 1024, height: 1366 },
        deviceScaleFactor: 2,
        hasTouch: true,
        isMobile: true,
      },
    },
    {
      name: "session-lifecycle",
      dependencies: [
        "chromium-desktop",
        "firefox-desktop",
        "webkit-desktop",
        "chromium-phone",
        "firefox-narrow",
        "webkit-iphone",
        "webkit-ipad",
      ],
      testMatch: lifecycleSpec,
      use: {
        ...authenticatedUse,
        browserName: "chromium",
        viewport: { width: 1440, height: 900 },
      },
    },
  ],
});
