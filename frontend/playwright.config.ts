import { defineConfig, devices } from '@playwright/test';

/**
 * End-to-end configuration.
 *
 * These tests drive a real browser against a running DroidScope stack. They do
 * not start the backend: a backend with a worker must already be running, which
 * keeps the browser tests honest about the real asynchronous behaviour.
 *
 *   DROIDSCOPE_E2E_BASE_URL  the frontend origin (default http://localhost:5173)
 */
const baseURL = process.env.DROIDSCOPE_E2E_BASE_URL ?? 'http://localhost:5173';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  timeout: 90_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],

  /*
   * In CI, Playwright starts and waits for the preview server itself, which is
   * far more reliable than backgrounding it in a shell step and polling.
   *
   * The explicit `--host 127.0.0.1` matters: `vite preview` otherwise binds to
   * `localhost`, which resolves to ::1 first on GitHub runners, so a client
   * connecting to 127.0.0.1 is refused.
   *
   * Locally the variable is unset, so the suite runs against whatever stack is
   * already running.
   */
  webServer: process.env.DROIDSCOPE_E2E_START_SERVER
    ? {
        command: 'npx vite preview --port 5173 --strictPort --host 127.0.0.1',
        url: 'http://127.0.0.1:5173',
        reuseExistingServer: false,
        timeout: 120_000,
        stdout: 'pipe',
        stderr: 'pipe',
      }
    : undefined,
});
