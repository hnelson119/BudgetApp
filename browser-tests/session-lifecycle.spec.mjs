import { expect, test } from "@playwright/test";

import { expectCleanPage, monitorPage } from "./support.mjs";

test("logout clears browser state and history cannot reveal protected content", async ({
  page,
  context,
  browser,
}) => {
  const signals = monitorPage(page);
  await page.goto("/audit/");
  await expect(page.getByRole("heading", { name: "Protected audit history" })).toBeVisible();

  const storedKeys = await page.evaluate(() => ({
    local: Object.keys(window.localStorage),
    session: Object.keys(window.sessionStorage),
  }));
  expect(storedKeys.local.every((key) => key === "household-budget-theme")).toBe(true);
  expect(storedKeys.session).toEqual([]);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/accounts\/login\/$/u);
  expect(
    (await context.cookies()).some((cookie) => cookie.name === "pentest_budget_sessionid"),
  ).toBe(false);

  await page.goBack();
  await expect(page).toHaveURL(/\/accounts\/login\//u);
  await expect(page.getByRole("heading", { name: "Protected audit history" })).toHaveCount(0);

  const freshContext = await browser.newContext({ baseURL: "http://pentest-web:8000" });
  try {
    const freshPage = await freshContext.newPage();
    await freshPage.goto("/");
    await expect(freshPage).toHaveURL(/\/accounts\/login\//u);
    await expect(freshPage.getByRole("heading", { name: "Sign in" })).toBeVisible();
  } finally {
    await freshContext.close();
  }
  expectCleanPage(signals);
});
