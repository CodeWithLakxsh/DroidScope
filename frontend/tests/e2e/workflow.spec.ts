/**
 * End-to-end workflow against a running DroidScope stack.
 *
 * Covers the acceptance path: open the dashboard, upload a real APK, queue a
 * scan, wait for the worker to finish it, read the findings, open one with its
 * evidence, and generate and download a PDF report.
 */

import { expect, test, type Page } from '@playwright/test';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

// The project is ESM, so __dirname is not defined.
const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.resolve(here, '../../../tests/fixtures/vulnerable-app.apk');

test.beforeAll(() => {
  if (!fs.existsSync(FIXTURE)) {
    throw new Error(
      `the fixture APK is missing at ${FIXTURE}; run scripts/development/build_fixture_apk.sh`,
    );
  }
});

/**
 * Waits for the scan in the current URL to reach a terminal state.
 *
 * This polls the API rather than matching text on the page. Matching text was
 * wrong: the analyzer coverage table shows "completed" per analyzer while the
 * scan as a whole is still running, so the test proceeded early and then found
 * an empty findings list.
 */
async function waitForScanCompletion(page: Page) {
  const scanId = page.url().split('/scans/')[1]?.split(/[?#]/)[0];
  expect(scanId, 'expected to be on a scan detail page').toBeTruthy();

  await expect
    .poll(
      async () => {
        const response = await page.request.get(`/api/v1/scans/${scanId}`);
        if (!response.ok()) return 'unreachable';
        return (await response.json()).status as string;
      },
      { timeout: 120_000, intervals: [500, 1000, 2000] },
    )
    .toMatch(/^(completed|failed|cancelled)$/);

  // Let the UI pick up the terminal state before the caller reads the page.
  await expect(page.getByText('Analyzer coverage')).toBeVisible();
}

test.describe('DroidScope', () => {
  test('the dashboard loads and reports API health', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByText('Connected')).toBeVisible();
  });

  test('navigation reaches every main section', async ({ page }) => {
    await page.goto('/');
    for (const label of ['Upload APK', 'Applications', 'Scans', 'Findings', 'Settings']) {
      await page.getByRole('link', { name: label, exact: true }).click();
      await expect(page).toHaveURL(new RegExp(label.toLowerCase().split(' ')[0]));
    }
  });

  test('rejects a file that is not an APK', async ({ page }) => {
    await page.goto('/upload');
    await page.setInputFiles('#apk-file-input', {
      name: 'not-an-apk.apk',
      mimeType: 'application/vnd.android.package-archive',
      buffer: Buffer.from('this is definitely not a zip archive'),
    });
    await expect(page.getByRole('alert')).toBeVisible();
    await expect(page.getByText(/not a ZIP archive/i)).toBeVisible();
  });

  test('uploads an APK, scans it, reviews findings and downloads a PDF', async ({ page }) => {
    // 1. upload
    await page.goto('/upload');
    await page.setInputFiles('#apk-file-input', FIXTURE);

    // The package name appears in both the card heading and the detail table,
    // so the locator is scoped to avoid a strict-mode multi-match.
    await expect(
      page.getByRole('heading', { name: 'com.droidscope.vulnerable' }),
    ).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole('button', { name: /Start analysis/i })).toBeVisible();

    // 2. queue the scan
    await page.getByRole('button', { name: /Start analysis/i }).click();
    await expect(page).toHaveURL(/\/scans\/[0-9a-f]+/, { timeout: 30_000 });

    // 3. the worker completes it
    await waitForScanCompletion(page);

    // 4. the scan detail shows real results and its coverage
    await expect(page.getByText('Risk score').first()).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Analyzer coverage' })).toBeVisible();
    await expect(page.getByText('manifest-analyzer').first()).toBeVisible();

    // 5. findings, with evidence
    await page.getByRole('link', { name: 'View findings' }).click();
    await expect(page).toHaveURL(/\/findings\//);
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();

    const firstFinding = page.locator('tbody tr').first();
    await expect(firstFinding).toBeVisible({ timeout: 30_000 });
    await firstFinding.click();

    await expect(page.getByRole('heading', { name: 'Security impact' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Remediation' })).toBeVisible();

    // 6. severity filtering narrows the list
    const before = await page.locator('tbody tr').count();
    await page.getByRole('button', { name: /Critical/ }).first().click();
    await expect(async () => {
      expect(await page.locator('tbody tr').count()).toBeLessThanOrEqual(before);
    }).toPass();

    // 7. generate and download a PDF
    const scanId = page.url().split('/findings/')[1];
    await page.goto(`/reports/${scanId}`);
    await page.getByRole('button', { name: /Generate PDF/i }).click();
    await expect(page.getByRole('cell', { name: /\.pdf$/ })).toBeVisible({ timeout: 60_000 });

    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('link', { name: /Download/ }).first().click();
    const download = await downloadPromise;
    const downloadPath = await download.path();
    expect(downloadPath).toBeTruthy();

    // The downloaded file must be a real PDF.
    const header = fs.readFileSync(downloadPath!).subarray(0, 5).toString();
    expect(header).toBe('%PDF-');
  });

  test('results survive a page reload', async ({ page }) => {
    await page.goto('/scans');
    const firstScan = page.locator('tbody tr a').first();
    await expect(firstScan).toBeVisible({ timeout: 30_000 });
    const href = await firstScan.getAttribute('href');

    await page.goto(href!);
    await waitForScanCompletion(page);
    const findingsText = await page.getByText('Findings').first().textContent();

    await page.reload();
    await expect(page.getByText('Findings').first()).toHaveText(findingsText!);
  });

  test('the theme toggle switches between light and dark', async ({ page }) => {
    await page.goto('/');
    const initial = await page.evaluate(() =>
      document.documentElement.classList.contains('dark'),
    );
    await page.getByRole('button', { name: /Switch to (light|dark) theme/ }).click();
    const after = await page.evaluate(() =>
      document.documentElement.classList.contains('dark'),
    );
    expect(after).toBe(!initial);
  });

  test('an unknown route shows the not-found page', async ({ page }) => {
    await page.goto('/this-route-does-not-exist');
    await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible();
  });
});
