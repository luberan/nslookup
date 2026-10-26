import { expect, test } from "@playwright/test";

test("temporary CI artifact verification probe", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop", "One diagnostic failure is sufficient.");
  await page.route("https://www.lukasberan.cz/img/logo.png", (route) => route.fulfill({ status: 204 }));
  await page.goto("/");
  expect(false, "Intentional diagnostic probe; remove before merging.").toBe(true);
});
