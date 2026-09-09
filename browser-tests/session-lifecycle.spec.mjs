import { expect, test } from "@playwright/test";

import { expectCleanPage, monitorPage } from "./support.mjs";

test("logout scrubs authenticated DOM and storage without a server response", async ({ page }) => {
  await page.goto("/audit/");
  await expect(page.getByRole("heading", { name: "Protected audit history" })).toBeVisible();

  await page.evaluate(async () => {
    window.localStorage.setItem("private-local-state", "sensitive");
    window.sessionStorage.setItem("private-session-state", "sensitive");
    if ("caches" in window) {
      const cache = await window.caches.open("private-cache");
      await cache.put("/private-cache-entry", new Response("sensitive"));
    }
    if (typeof window.indexedDB?.databases === "function") {
      await new Promise((resolve, reject) => {
        const request = window.indexedDB.open("private-database", 1);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          request.result.close();
          resolve();
        };
      });
    }

    const form = document.querySelector("form[data-terminate-session]");
    form.addEventListener("submit", (event) => event.preventDefault(), { once: true });
    form.requestSubmit();
  });

  await expect(page.getByRole("heading", { name: "Protected audit history" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Signing out" })).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(async () => ({
        local: Object.keys(window.localStorage),
        session: Object.keys(window.sessionStorage),
        caches: "caches" in window ? await window.caches.keys() : [],
        databases:
          typeof window.indexedDB?.databases === "function"
            ? (await window.indexedDB.databases())
                .map((database) => database.name)
                .filter(Boolean)
            : [],
      })),
    )
    .toEqual({ local: [], session: [], caches: [], databases: [] });
});

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
