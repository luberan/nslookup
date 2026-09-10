import { defineConfig } from "@playwright/test";

const port = Number(process.env.PLAYWRIGHT_PORT || 8975);
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./test/browser",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  workers: 2,
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1280, height: 900 } } },
    { name: "mobile", use: { viewport: { width: 375, height: 812 } } },
    { name: "narrow", use: { viewport: { width: 320, height: 780 } } },
  ],
  webServer: {
    command: `wrangler dev --ip 127.0.0.1 --port ${port} --inspector-port 0 --local`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 30000,
  },
});