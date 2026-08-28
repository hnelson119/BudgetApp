import { chmodSync, mkdirSync } from "node:fs";

import { expect, test as setup } from "@playwright/test";

import {
  currentTotpCode,
  expectCleanPage,
  monitorPage,
  readSyntheticSecret,
} from "./support.mjs";

const authenticationState = "/tmp/browser-auth/alex.json";

setup("authenticate through the real password and TOTP browser flow", async ({ page, context }) => {
  const signals = monitorPage(page);
  const password = readSyntheticSecret("/run/browser-credentials/alex_password");
  const totpSecret = readSyntheticSecret("/run/browser-credentials/alex_totp");

  const response = await page.goto("/audit/");
  expect(response?.status()).toBe(200);
  await expect(page).toHaveURL(/\/accounts\/login\/\?next=(?:%2F|\/)audit(?:%2F|\/)$/iu);
  await page.getByLabel(/email/iu).fill("alex.pentest@budget.invalid");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Continue securely" }).click();
  await expect(page).toHaveURL(/\/accounts\/mfa\/verify\//u);
  await page.getByLabel(/code/iu).fill(currentTotpCode(totpSecret));
  await page.getByRole("button", { name: "Verify and sign in" }).click();

  await expect(page).toHaveURL(/\/audit\/$/u);
  await expect(page.getByRole("heading", { name: "Protected audit history" })).toBeVisible();
  const sessionCookie = (await context.cookies()).find(
    (cookie) => cookie.name === "pentest_budget_sessionid",
  );
  expect(sessionCookie?.httpOnly).toBe(true);
  expect(sessionCookie?.sameSite).toBe("Strict");
  expect(sessionCookie?.expires).toBe(-1);

  mkdirSync("/tmp/browser-auth", { recursive: true, mode: 0o700 });
  await context.storageState({ path: authenticationState });
  chmodSync(authenticationState, 0o400);
  expectCleanPage(signals);
});
