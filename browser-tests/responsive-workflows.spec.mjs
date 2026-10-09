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

async function expectDebtSpacing(page) {
  const collisions = await page.locator(".debt-workspace").evaluate((workspace) => {
    const problems = [];
    const panels = [...workspace.querySelectorAll(":scope > .summary-grid, :scope > .form-card, :scope > .transaction-panel")];
    for (let index = 1; index < panels.length; index += 1) {
      if (panels[index].getBoundingClientRect().top - panels[index - 1].getBoundingClientRect().bottom < 20) {
        problems.push("Page sections need at least 20px of separation");
      }
    }
    for (const card of workspace.querySelectorAll(".form-page > .form-card + .form-card")) {
      if (card.getBoundingClientRect().top - card.previousElementSibling.getBoundingClientRect().bottom < 20) {
        problems.push("Calculator result cards touch the input card");
      }
    }
    for (const helper of workspace.querySelectorAll("td > small")) {
      const previous = helper.previousSibling;
      if (!previous || !previous.textContent.trim()) continue;
      const range = document.createRange();
      range.selectNodeContents(previous);
      if (helper.getBoundingClientRect().top - range.getBoundingClientRect().bottom < 3) {
        problems.push("Table helper text collides with the value or preceding message");
      }
    }
    for (const heading of workspace.querySelectorAll(".debt-panel > .section-title")) {
      const panel = heading.parentElement.getBoundingClientRect();
      const title = heading.firstElementChild.getBoundingClientRect();
      if (title.left - panel.left < 16 || title.top - panel.top < 16) {
        problems.push("Panel heading lacks border padding");
      }
    }
    return problems;
  });
  expect(collisions).toEqual([]);
}

test("bill cadence date inputs stay compact and clear of weekday choices", async ({ page }) => {
  const signals = monitorPage(page);
  await page.goto("/budget/");
  await page.getByRole("link", { name: "Add fixed expense", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Describe the bill cadence", exact: true })).toBeVisible();
  for (const dateValue of ["", "2027-12-31"]) {
    await page.locator("#id_end_date").fill(dateValue);
    const problems = await page.locator(".schedule-form").evaluate((form) => {
      const failures = [];
      const weekdays = form.querySelector("#id_weekdays").getBoundingClientRect();
      for (const input of form.querySelectorAll('input[type="date"]')) {
        const rect = input.getBoundingClientRect();
        const field = input.closest(".form-field").getBoundingClientRect();
        if (rect.height < 44 || rect.height > 48) failures.push("Date input height");
        if (rect.left < field.left - 1 || rect.right > field.right + 1) failures.push("Date input width");
        if (rect.left < weekdays.right && rect.right > weekdays.left
          && rect.top < weekdays.bottom && rect.bottom > weekdays.top) failures.push("Date overlaps weekdays");
      }
      return failures;
    });
    expect(problems).toEqual([]);
    await expectNoHorizontalOverflow(page);
  }
  const monday = page.getByLabel("Monday", { exact: true });
  await monday.check();
  await expect(monday).toBeChecked();
  expectCleanPage(signals);
});

test("monthly budget balancing previews household periods without changing the plan", async ({ page }) => {
  const signals = monitorPage(page);
  await page.goto("/budget/");
  await page.getByRole("link", { name: "Balance this month", exact: true }).click();
  const preview = page.getByRole("region", { name: "Monthly budget balance", exact: true });
  await expect(preview).toBeVisible();
  await expect(preview.getByRole("columnheader", { name: "Headroom now", exact: true })).toBeVisible();
  await expect(preview).toContainText("No payments are sent");
  await expectNoHorizontalOverflow(page);
  expectCleanPage(signals);
});

test("household payoff plans preview before saving and fit the viewport", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  const response = await page.goto("/debts/plan/");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Household payoff plan", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save household plan", exact: true })).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    await page.getByLabel("Strategy").selectOption("avalanche");
    await page.getByLabel("Extra per household paycheck period").fill("0.00");
    await page.getByLabel("Cash cushion to keep unallocated").fill("25.00");
    await page.getByRole("button", { name: "Preview payoff plan", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Payoff forecast", exact: true })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.getByRole("button", { name: "Save household plan", exact: true }).click();
    await expect(page).toHaveURL(/\/debts\/$/u);
    await expect(page.getByRole("region", { name: "Household payoff plan" })).toContainText("Avalanche");
    await page.getByRole("link", { name: /^Plan extra:/u }).first().click();
    await expect(page.getByRole("heading", { name: "Plan an extra debt payment", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add extra payment to Budget", exact: true })).toHaveCount(0);
    await expectNoHorizontalOverflow(page);
  }
  expectCleanPage(signals);
});

test("debt details can be edited and saved against PostgreSQL", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  await page.goto("/debts/");
  await page.locator(".debt-table").getByRole("link", { name: "View", exact: true }).first().click();
  const debtUrl = page.url();
  await page.getByRole("link", { name: "Edit details", exact: true }).click();
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    const originalName = await page.getByLabel("Name").inputValue();
    const originalNotes = await page.getByLabel("Notes").inputValue();
    const originalAccount = await page.getByLabel("Financial account").inputValue();
    const renamed = `Edited ${testInfo.project.name}`;
    await page.getByLabel("Name").fill(renamed);
    await page.getByLabel("Notes").fill("Browser-tested metadata update");
    await page.getByLabel("Reason").fill("Verify debt editing saves successfully");
    const saved = page.waitForResponse((response) =>
      response.request().method() === "POST" && response.url().endsWith("/edit/"),
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect((await saved).status()).toBe(302);
    await expect(page).toHaveURL(debtUrl);
    await page.getByRole("link", { name: "Edit details", exact: true }).click();
    await expect(page.getByLabel("Name")).toHaveValue(renamed);
    await expect(page.getByLabel("Notes")).toHaveValue("Browser-tested metadata update");
    await page.getByLabel("Financial account").selectOption("");
    await page.getByLabel("Reason").fill("Verify optional ledger account can be removed");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page).toHaveURL(debtUrl);
    await page.getByRole("link", { name: "Edit details", exact: true }).click();
    await expect(page.getByLabel("Financial account")).toHaveValue("");
    await page.getByLabel("Name").fill(originalName);
    await page.getByLabel("Notes").fill(originalNotes);
    await page.getByLabel("Financial account").selectOption(originalAccount);
    await page.getByLabel("Reason").fill("Restore disposable fixture details");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page).toHaveURL(debtUrl);
  }
  expectCleanPage(signals);
});

test("promotional lender terms can be saved with a visible deadline", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  await page.goto("/debts/");
  await page.locator(".debt-table").getByRole("link", { name: "View", exact: true }).first().click();
  await page.getByRole("link", { name: "Track promotional terms", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Promotional debt terms", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    await page.getByLabel("Promotion type").selectOption("introductory");
    const today = new Date();
    const expiry = new Date(today);
    expiry.setUTCDate(expiry.getUTCDate() + 90);
    await page.getByLabel("Pay-in-full deadline / last promotional day").fill(expiry.toISOString().slice(0, 10));
    await page.getByLabel("Promotional APR (%)").fill("0.00");
    await page.getByLabel("APR after promotion / deferred-interest APR (%)").fill("24.99");
    await page.getByLabel("Lender-reported accrued deferred interest").fill("");
    await page.getByLabel("This promotion covers the entire balance").check();
    await page.getByLabel("I reviewed these lender terms").check();
    await page.getByRole("button", { name: "Save promotional terms", exact: true }).click();
    await expect(page.getByRole("region", { name: "Promotional payoff target" })).toContainText("24.9900%");
    await expectNoHorizontalOverflow(page);
    await page.goto("/debts/");
    await expect(page.getByRole("region", { name: "Promotion deadlines" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
  }
  expectCleanPage(signals);
});

test("target and offer calculators show estimates without changing debts", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  await page.goto("/debts/");
  await expect(page.getByRole("region", { name: "Debt progress", exact: true })).toBeVisible();
  await expectDebtSpacing(page);
  await expectNoHorizontalOverflow(page);
  await page.getByRole("link", { name: "Calculate debt-free target", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Debt-free target calculator", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    await page.getByLabel("Strategy").selectOption("avalanche");
    const target = new Date();
    target.setUTCDate(target.getUTCDate() + 365);
    await page.getByLabel("Debt-free target date").fill(target.toISOString().slice(0, 10));
    await page.getByLabel("Maximum extra per household paycheck period").fill("5000.00");
    await page.getByRole("button", { name: "Calculate target", exact: true }).click();
    await expect(page.getByRole("region", { name: "Target result", exact: true })).toBeVisible();
    await expectDebtSpacing(page);
    await expectNoHorizontalOverflow(page);
  }
  await page.goto("/debts/");
  await page.locator(".debt-table").getByRole("link", { name: "View", exact: true }).first().click();
  await page.getByRole("link", { name: "Compare refinancing / transfer", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Refinancing & balance-transfer comparison", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    await page.getByLabel("Offer annual interest rate (%)").fill("0.00");
    await page.getByLabel("Offer monthly payment toward principal and interest").fill("500.00");
    await page.getByLabel("Transfer / origination fee (%)").fill("3.00");
    await page.getByLabel("Other upfront fees / closing costs").fill("25.00");
    await page.getByLabel("Add fees to the new balance").check();
    await page.getByRole("button", { name: "Compare offer", exact: true }).click();
    await expect(page.getByRole("region", { name: "Offer comparison", exact: true })).toBeVisible();
    await expectDebtSpacing(page);
    await expectNoHorizontalOverflow(page);
  }
  expectCleanPage(signals);
});

test("payoff comparisons can focus on a selected debt", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  await page.goto("/debts/projections/");
  const choices = page.locator("#id_debts input[type=checkbox]");
  expect(await choices.count()).toBeGreaterThan(0);
  await expect(choices.first()).toBeChecked();
  await expect(page.locator(".form-card .payoff-filter-bar")).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
  if (testInfo.project.name.endsWith("-desktop")) {
    const count = await choices.count();
    for (let index = 1; index < count; index += 1) await choices.nth(index).uncheck();
    await page.getByLabel("Monthly strategy extra").fill("200.00");
    await page.getByRole("button", { name: "Run comparison", exact: true }).click();
    await expect(page.getByText(/^Comparing 1 selected debt:/u)).toBeVisible();
    await expect(page.locator("#id_debts input[type=checkbox]:checked")).toHaveCount(1);
    await expectDebtSpacing(page);
    const planLink = page.getByRole("link", { name: "Build a saved paycheck payoff plan", exact: true });
    const linkGap = await planLink.evaluate((link) =>
      link.getBoundingClientRect().top - link.previousElementSibling.getBoundingClientRect().bottom,
    );
    expect(linkGap).toBeGreaterThanOrEqual(20);
    await expectNoHorizontalOverflow(page);
  }
  expectCleanPage(signals);
});

test("income schedules can be edited after creation", async ({ page }, testInfo) => {
  const signals = monitorPage(page);
  const sourceName = `Editable paycheck ${testInfo.project.name}`;
  const response = await page.goto("/spending/income/schedules/add/");
  expect(response?.status()).toBe(200);
  await page.getByLabel("Income source").fill(sourceName);
  await page.getByLabel("Expected take-home amount").fill("1250.00");
  await page.getByLabel("Frequency").selectOption("biweekly");
  const futurePayday = new Date();
  futurePayday.setUTCDate(futurePayday.getUTCDate() + 28);
  await page.getByLabel("First payday").fill(futurePayday.toISOString().slice(0, 10));
  await page.getByLabel("Start a budget period on each payday").uncheck();
  await page.getByRole("button", { name: "Preview paydays", exact: true }).click();
  await page.getByRole("button", { name: "Create income schedule", exact: true }).click();
  const schedule = page.locator(".form-card").filter({
    has: page.getByRole("heading", { name: sourceName, exact: true }),
  });
  await schedule.getByRole("link", { name: "Edit schedule", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Edit income schedule", exact: true })).toBeVisible();
  await expect(page.getByLabel("Income source")).toHaveValue(sourceName);
  await expect(page.getByLabel("Frequency")).toHaveValue("biweekly");
  await page.getByLabel("Expected take-home amount").fill("1500.25");
  await page.getByLabel("Reason for change").fill("Synthetic paycheck correction");
  await page.getByLabel("Start a budget period on each payday").check();
  await page.getByRole("button", { name: "Preview paydays", exact: true }).click();
  await expect(page.getByText("Next three paydays", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await page.getByRole("button", { name: "Save schedule changes", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Income schedules", exact: true })).toBeVisible();
  await expect(page.locator(".form-card").filter({
    has: page.getByRole("heading", { name: sourceName, exact: true }),
  })).toContainText("1,500.25");
  await expect(page.locator(".form-card").filter({
    has: page.getByRole("heading", { name: sourceName, exact: true }),
  })).toContainText("Starts household budget periods");
  const incomeGaps = await page.locator(".income-schedule-list").evaluate((list) => {
    const cards = [...list.children];
    const heading = list.previousElementSibling.getBoundingClientRect();
    return cards.map((card, index) => card.getBoundingClientRect().top
      - (index ? cards[index - 1].getBoundingClientRect().bottom : heading.bottom));
  });
  expect(incomeGaps.length).toBeGreaterThan(1);
  for (const gap of incomeGaps) expect(gap).toBeGreaterThanOrEqual(20);
  await expectNoHorizontalOverflow(page);
  await page.goto("/");
  await expectNoHorizontalOverflow(page);
  expectCleanPage(signals);
});

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
    ["Budget", "Budget"],
    ["Income", "Income"],
    ["Spending", "Spending & transactions"],
    ["Debts", "Debts & payoff"],
    ["Goals", "Goals"],
  ]) {
    const navigation = narrow
      ? page.getByRole("navigation", { name: "Mobile navigation" })
      : page.getByRole("complementary", { name: "Primary navigation" });
    await navigation.getByRole("link", { name, exact: true }).click();
    await expect(
      page.getByRole("heading", { name: heading, exact: true, level: 1 }),
    ).toBeVisible();
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
