import { _electron as electron, expect, test } from "@playwright/test";
import path from "node:path";

const appRoot = path.resolve(__dirname, "..", "..");

test("navigation and simulator events", async () => {
  const app = await electron.launch({
    args: ["."],
    cwd: appRoot,
    env: {
      ...process.env,
      AYDO_ENGINE: "simulator",
      AYDO_SIM_FAST: "1",
      AYDO_AUTH_OFFLINE: "1"
    }
  });

  try {
    const page = await app.firstWindow();

    await expect(page.getByText("Threat Operations Login")).toBeVisible();

    await page.locator("input[type=\"email\"]").fill("analyst@aydo.local");
    await page.locator("input[type=\"password\"]").fill("password123");
    await page.getByRole("button", { name: "Access Console" }).click();

    await expect(page.getByText("Dashboard")).toBeVisible();
    await expect(page.getByText("Protection Pulse")).toBeVisible();

    await page.getByRole("button", { name: "Start Scan" }).click();
    await expect(page.getByText(/Scan running/i)).toBeVisible();
    await expect(page.getByText("Scan completed")).toBeVisible({ timeout: 20_000 });

    await page.getByRole("link", { name: "Settings" }).click();
    await expect(page.getByText("Threat Thresholds")).toBeVisible();

    await page.getByRole("link", { name: "Dashboard" }).click();
    await expect(page.getByText("Engine Logs")).toBeVisible();
  } finally {
    await app.close();
  }
});
