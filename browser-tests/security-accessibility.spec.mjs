import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import {
  expectCleanPage,
  expectNoHorizontalOverflow,
  formatAxeViolations,
  monitorPage,
} from "./support.mjs";

test("authenticated pages preserve browser security controls", async ({ page, context }) => {
  const signals = monitorPage(page);
  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  const headers = response?.headers() ?? {};
  expect(headers["cache-control"]).toBe("no-store, private");
  expect(headers.pragma).toBe("no-cache");
  expect(headers["content-security-policy"]).toContain("default-src 'self'");
  expect(headers["content-security-policy"]).toContain("script-src 'self'");
  expect(headers["content-security-policy"]).not.toContain("'unsafe-inline'");
  expect(headers["content-security-policy"]).not.toContain("'unsafe-eval'");
  expect(headers["permissions-policy"]).toBe("camera=(), microphone=(), geolocation=()");
  expect(headers["x-frame-options"]).toBe("DENY");

  const sessionCookie = (await context.cookies()).find(
    (cookie) => cookie.name === "pentest_budget_sessionid",
  );
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(sessionCookie?.sameSite).toBe("Strict");
  expect(sessionCookie?.expires).toBe(-1);
  const browserStorage = await page.evaluate(() => ({
    localKeys: Object.keys(window.localStorage),
    sessionKeys: Object.keys(window.sessionStorage),
  }));
  expect(browserStorage.localKeys).toEqual([]);
  expect(browserStorage.sessionKeys).toEqual([]);
  expectCleanPage(signals);
});

test("filter and fragment payloads remain inert under the CSP", async ({ page }) => {
  const signals = monitorPage(page);
  const payload = '<img src=x onerror="window.__budgetInjected=true">';
  const response = await page.goto(`/spending/?scope=all&q=${encodeURIComponent(payload)}#${encodeURIComponent(payload)}`);
  expect(response?.status()).toBe(200);
  await expect(page.locator('input[name="q"]')).toHaveValue(payload);
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(await page.evaluate(() => window.__budgetInjected)).toBeUndefined();
  expect(response?.headers()["content-security-policy"]).toContain("script-src 'self'");
  expectCleanPage(signals);
});

test("key authenticated pages have no automated WCAG A or AA violations", async ({ page }) => {
  for (const path of ["/", "/debts/", "/goals/", "/accounts/security/"]) {
    await page.goto(path);
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(results.violations, formatAxeViolations(results.violations)).toEqual([]);
  }
});

test("public password recovery is accessible and responsive without authentication", async ({
  page,
  context,
}) => {
  await context.clearCookies();
  const signals = monitorPage(page);
  const response = await page.goto("/accounts/recover/");
  expect(response?.status()).toBe(200);
  expect(response?.headers()["cache-control"]).toContain("no-store");
  await expect(page.getByRole("heading", { name: "Recover your password" })).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveAttribute("autocomplete", "username");
  await expect(page.getByLabel("Authenticator or recovery code")).toHaveAttribute(
    "autocomplete",
    "one-time-code",
  );
  await expect(page.getByLabel("New password", { exact: true })).toHaveAttribute(
    "autocomplete",
    "new-password",
  );
  await expect(page.getByLabel("Confirm new password")).toHaveAttribute(
    "autocomplete",
    "new-password",
  );
  await expectNoHorizontalOverflow(page);
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations, formatAxeViolations(results.violations)).toEqual([]);
  expectCleanPage(signals);
});
