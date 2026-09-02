import { expect, test } from "@playwright/test";

import { expectCleanPage, expectNoHorizontalOverflow, monitorPage } from "./support.mjs";

async function selectOptionContaining(control, visibleText) {
  const value = await control
    .locator("option")
    .filter({ hasText: visibleText })
    .getAttribute("value");
  expect(value, `An option containing ${visibleText} should exist.`).not.toBeNull();
  await control.selectOption(value);
}

test("navigation, theme, and layouts work at the configured viewport", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("button", { name: "Switch color theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await page.evaluate(() => Object.keys(window.localStorage))).toEqual([
    "household-budget-theme",
  ]);

  const narrow = testInfo.project.use.viewport.width <= 850;
  if (narrow) {
    await expect(page.getByRole("navigation", { name: "Mobile navigation" })).toBeVisible();
    await expect(page.getByRole("complementary", { name: "Primary navigation" })).toBeHidden();
  } else {
    await expect(page.getByRole("navigation", { name: "Mobile navigation" })).toBeHidden();
    await expect(page.getByRole("complementary", { name: "Primary navigation" })).toBeVisible();
  }

  await expectNoHorizontalOverflow(page);
  for (const [name, heading] of [
    ["Spending", "Spending & transactions"],
    ["Debts", "Debts & payoff"],
    ["Goals", "Goals"],
  ]) {
    const navigation = narrow
      ? page.getByRole("navigation", { name: "Mobile navigation" })
      : page.getByRole("complementary", { name: "Primary navigation" });
    await navigation.getByRole("link", { name, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  }
  await page.locator(".topbar-actions").getByRole("link", { name: "Account security" }).click();
  await expect(page.getByRole("heading", { name: "Account security", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Active sessions", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  expectCleanPage(signals);
});

test("desktop keyboard users can skip repetitive navigation and see focus", async ({ page }, testInfo) => {
  test.skip(!testInfo.project.name.endsWith("-desktop"), "Desktop keyboard proof only.");
  const signals = monitorPage(page);
  await page.goto("/");

  const skipLink = page.getByRole("link", { name: "Skip to main content" });
  await page.keyboard.press("Tab");
  await expect(skipLink).toBeFocused();
  await expect(skipLink).toBeVisible();
  expect(
    await skipLink.evaluate((element) => window.getComputedStyle(element).outlineStyle),
  ).not.toBe("none");

  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.locator(".topbar-actions").getByRole("link", { name: "Account security" }),
  ).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: /Notifications/iu })).toBeFocused();
  await page.keyboard.press("Tab");
  const themeButton = page.getByRole("button", { name: "Switch color theme" });
  await expect(themeButton).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  for (const placeholder of await page.locator('a[aria-disabled="true"]').all()) {
    await expect(placeholder).not.toHaveAttribute("href");
    await expect(placeholder).toHaveAttribute("tabindex", "-1");
  }
  expectCleanPage(signals);
});

test("primary touch navigation targets are at least 44 CSS pixels", async ({ page }, testInfo) => {
  const mobileProjects = new Set([
    "chromium-phone",
    "firefox-narrow",
    "webkit-iphone",
    "webkit-ipad",
  ]);
  test.skip(!mobileProjects.has(testInfo.project.name), "Mobile and narrow viewport proof only.");
  const signals = monitorPage(page);
  await page.goto("/");

  const narrow = testInfo.project.use.viewport.width <= 850;
  const targets = narrow
    ? page.getByRole("navigation", { name: "Mobile navigation" }).getByRole("link")
    : page.locator(".app-nav a");
  expect(await targets.count()).toBeGreaterThanOrEqual(5);
  for (const target of await targets.all()) {
    const box = await target.boundingBox();
    expect(box, "A mobile navigation target should have a rendered box.").not.toBeNull();
    expect(box.height).toBeGreaterThanOrEqual(44);
  }
  expectCleanPage(signals);
});

test("a manual expense can be entered without exposing browser-only state", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  const description = `Browser smoke ${testInfo.project.name}`;
  const response = await page.goto("/spending/expenses/add/");
  expect(response?.status()).toBe(200);
  await expect(page).toHaveURL(/\/spending\/expenses\/add\/$/u);
  await expect(page.locator(".form-card h2")).toHaveText("Record expense");
  await page.getByLabel("Description").fill(description);
  await page.getByLabel("Amount").fill("12.34");
  await page.getByLabel("Paid from account or card").selectOption({
    label: "Synthetic Checking · Checking",
  });
  await selectOptionContaining(page.getByLabel("Category"), "Groceries");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  await expect(page.getByText(description, { exact: true })).toBeVisible();
  await page.goto(`/spending/?scope=all&q=${encodeURIComponent(description)}`);
  await expect(page.getByText(description, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(window.sessionStorage))).toEqual([]);
  expectCleanPage(signals);
});

test("category budget deletion requires explicit confirmation", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "chromium-desktop", "One destructive-flow proof is sufficient.");
  const signals = monitorPage(page);
  await page.goto("/");
  await page.getByRole("link", { name: /Open full budget/iu }).click();
  await page.getByRole("link", { name: "Add category budget" }).click();
  await expect(page.locator(".form-card h2")).toHaveText("Add category budget");
  await selectOptionContaining(page.getByLabel("Category"), "Groceries");
  await page.getByLabel("Planned amount").fill("125.00");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const budgetCard = page.locator(".category-budget-grid article").filter({ hasText: "Groceries" });
  await expect(budgetCard).toBeVisible();
  await budgetCard.getByRole("link", { name: "Remove" }).click();
  await expect(page.getByRole("heading", { name: "Remove Groceries?" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Remove category budget" })).toBeVisible();
  await page.getByLabel("Reason", { exact: true }).fill("Automated deletion-confirmation proof");
  await page.getByLabel(/I understand this category budget will be removed/iu).check();
  await page.getByRole("button", { name: "Remove category budget" }).click();
  await expect(page.locator(".category-budget-grid article").filter({ hasText: "Groceries" })).toHaveCount(0);
  expectCleanPage(signals);
});
