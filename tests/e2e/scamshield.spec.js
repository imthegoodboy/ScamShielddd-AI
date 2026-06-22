import { expect, test } from "@playwright/test";

test("runs a job-scam investigation, saves history, and creates a PDF", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("response", (response) => {
    const url = response.url();
    if (response.status() >= 400 && !url.includes("/static/anna-apps/_sdk/latest/index.js")) {
      errors.push(`${response.status()} ${url}`);
    }
  });
  page.on("console", (msg) => {
    const text = msg.text();
    if (msg.type() === "error" && text !== "Failed to load resource: the server responded with a status of 404 (Not Found)") {
      errors.push(msg.text());
    }
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: /check the thing/i })).toBeVisible();
  await page.getByRole("button", { name: /job offer/i }).click();
  await page.getByLabel("Job offer text").fill(
    "Amazon Work From Home HR. Salary Rs 60,000 per month. Pay registration fee Rs 500 immediately to receive your interview letter.",
  );
  await page.getByRole("button", { name: "Investigate" }).click();

  await expect(page.getByText(/Likely scam job offer|High-risk job offer/)).toBeVisible();
  await expect(page.getByRole("listitem").filter({ hasText: "Job offer asks for money" }).first()).toBeVisible();
  await page.getByRole("tab", { name: "Actions" }).click();
  await expect(page.getByText("Do not click, pay, or reply")).toBeVisible();

  const pdfHref = await page.getByRole("link", { name: "Download PDF" }).getAttribute("href");
  expect(pdfHref).toMatch(/^blob:/);
  const pdfHeader = await page.evaluate(async (href) => {
    const res = await fetch(href);
    const buf = await res.arrayBuffer();
    return new TextDecoder().decode(new Uint8Array(buf.slice(0, 5)));
  }, pdfHref);
  expect(pdfHeader).toBe("%PDF-");

  await page.getByRole("button", { name: "Save report" }).click();
  await expect(page.getByText("Report saved.")).toBeVisible();
  await expect(page.locator(".history-row")).toHaveCount(1);
  expect(errors).toEqual([]);
});

for (const width of [320, 375, 414, 768]) {
  test(`renders without horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /check the thing/i })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    expect(overflow).toBe(false);
  });
}
