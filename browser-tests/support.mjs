import { createHmac } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";

import { expect } from "@playwright/test";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // pragma: allowlist secret

export function readSyntheticSecret(path) {
  const metadata = lstatSync(path);
  if (metadata.isSymbolicLink() || !metadata.isFile() || metadata.size > 16 * 1024) {
    throw new Error("A required synthetic browser credential file is invalid.");
  }
  const value = readFileSync(path, "ascii").trim();
  if (value.length < 16) {
    throw new Error("A required synthetic browser credential is too short.");
  }
  return value;
}

function decodeBase32(secret) {
  let buffer = 0;
  let bufferedBits = 0;
  const bytes = [];
  for (const character of secret.toUpperCase().replace(/=+$/u, "")) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value < 0) throw new Error("The synthetic TOTP secret is not valid base32.");
    buffer = (buffer << 5) | value;
    bufferedBits += 5;
    if (bufferedBits >= 8) {
      bufferedBits -= 8;
      bytes.push((buffer >>> bufferedBits) & 0xff);
      buffer &= (1 << bufferedBits) - 1;
    }
  }
  return Buffer.from(bytes);
}

export function currentTotpCode(secret) {
  const counter = Math.floor(Date.now() / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, "0");
}

export function monitorPage(page) {
  const signals = { dialogs: [], pageErrors: [] };
  page.on("dialog", async (dialog) => {
    signals.dialogs.push(dialog.type());
    await dialog.dismiss();
  });
  page.on("pageerror", (error) => signals.pageErrors.push(error.message));
  return signals;
}

export function expectCleanPage(signals) {
  expect(signals.dialogs, "No injected script should open a browser dialog.").toEqual([]);
  expect(signals.pageErrors, "Pages should not raise uncaught JavaScript errors.").toEqual([]);
}

export async function expectNoHorizontalOverflow(page) {
  const details = await page.evaluate(() => {
    const viewportWidth = window.innerWidth;
    const overflow = Math.max(0, document.documentElement.scrollWidth - viewportWidth);
    const offenders = [...document.querySelectorAll("body *")]
      .map((element) => {
        const rectangle = element.getBoundingClientRect();
        return {
          element: `${element.tagName.toLowerCase()}.${[...element.classList].join(".")}`,
          left: Math.round(rectangle.left),
          right: Math.round(rectangle.right),
          width: Math.round(rectangle.width),
        };
      })
      .filter(({ left, right }) => left < -1 || right > viewportWidth + 1)
      .slice(0, 8);
    return { overflow, path: window.location.pathname, viewportWidth, offenders };
  });
  expect(details.overflow, JSON.stringify(details, null, 2)).toBeLessThanOrEqual(1);
}

export function formatAxeViolations(violations) {
  return violations
    .map((violation) => {
      const targets = violation.nodes.flatMap((node) => node.target).join(", ");
      return `${violation.id} (${violation.impact ?? "unknown"}): ${targets}`;
    })
    .join("\n");
}
