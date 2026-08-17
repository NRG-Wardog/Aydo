import { _electron as electron, expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(testDirectory, "..", "..");

test("navigation and simulator events", async () => {
  const app = await electron.launch({
    args: [".", "--no-sandbox"],
    cwd: appRoot,
    env: {
      ...process.env,
      AYDO_ENGINE: "simulator",
      AYDO_SIM_FAST: "1",
      AYDO_AUTH_OFFLINE: "1",
      ELECTRON_DISABLE_SANDBOX: "1"
    }
  });

  try {
    const page = await app.firstWindow();

    await expect(page.getByText("Threat Operations Login")).toBeVisible();

    await page.getByRole("button", { name: "Continue as Guest" }).click();

    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await expect(page.getByText("Protection Pulse")).toBeVisible();

    await page.getByRole("button", { name: "Scan Directory", exact: true }).click();
    await expect(page.getByText("Select Directory to Scan")).toBeVisible();
    await page.getByRole("button", { name: "Scan Directory", exact: true }).last().click();
    await expect(page.getByText("Scan completed")).toBeVisible({ timeout: 20_000 });

    await page.getByRole("link", { name: "Settings" }).click();
    await expect(page.getByText("Threat Thresholds")).toBeVisible();

    await page.getByRole("link", { name: "Dashboard" }).click();
    await expect(page.getByText("Engine Logs")).toBeVisible();
  } finally {
    await app.close();
  }
});
