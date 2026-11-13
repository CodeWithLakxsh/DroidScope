/**
 * Captures screenshots of the running application for the documentation.
 *
 * These are real screenshots of real analysis results: the suite drives the
 * live UI against a live backend, so nothing here is mocked or staged.
 *
 *   npx playwright test screenshots --project=chromium
 */

import { expect, test } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT = path.resolve(here, '../../../docs/screenshots');

test.describe.configure({ mode: 'serial' });

async function settle(page: import('@playwright/test').Page) {
  await page.waitForLoadState('networkidle');
  // Let fonts and chart animations finish so captures are deterministic.
  await page.waitForTimeout(600);
}

test('capture dashboard', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'dashboard.png'), fullPage: true });
});

test('capture findings explorer', async ({ page }) => {
  await page.goto('/findings');
  await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible();
  const row = page.locator('tbody tr').first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  await expect(page.getByRole('heading', { name: 'Security impact' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'findings.png'), fullPage: false });
});

test('capture scan detail', async ({ page }) => {
  await page.goto('/scans');
  const link = page.locator('tbody tr a').first();
  await expect(link).toBeVisible({ timeout: 30_000 });
  await link.click();
  await expect(page.getByRole('heading', { name: 'Analyzer coverage' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'scan-detail.png'), fullPage: true });
});

test('capture code explorer', async ({ page }) => {
  await page.goto('/code');
  await page.waitForURL(/\/code\/[0-9a-f]+/, { timeout: 30_000 });
  const file = page.locator('button', { hasText: 'CryptoUtil.java' }).first();
  if (await file.count()) {
    await file.click();
    await page.waitForTimeout(2500); // Monaco needs a moment to paint
  }
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'code-explorer.png'), fullPage: false });
});

test('capture manifest explorer', async ({ page }) => {
  await page.goto('/applications');
  const link = page.locator('tbody tr a').first();
  await expect(link).toBeVisible({ timeout: 30_000 });
  const href = await link.getAttribute('href');
  await page.goto(href!.replace('/applications/', '/manifest/'));
  await expect(page.getByRole('heading', { name: 'Manifest explorer' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'manifest.png'), fullPage: true });
});

test('capture visualisations', async ({ page }) => {
  await page.goto('/graphs');
  await page.waitForURL(/\/graphs\/[0-9a-f]+/, { timeout: 30_000 });
  await expect(page.getByRole('heading', { name: 'Analysis pipeline' })).toBeVisible();
  await page.waitForTimeout(2000); // React Flow layout
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'visualisations.png'), fullPage: true });
});

test('capture indicators', async ({ page }) => {
  await page.goto('/indicators');
  await page.waitForURL(/\/indicators\/[0-9a-f]+/, { timeout: 30_000 });
  await expect(page.getByRole('heading', { name: 'Network indicators' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'indicators.png'), fullPage: true });
});

test('capture upload page in light theme', async ({ page }) => {
  await page.goto('/');
  // Switch to light so the documentation shows both themes.
  const toggle = page.getByRole('button', { name: /Switch to light theme/ });
  if (await toggle.count()) await toggle.click();
  await page.goto('/upload');
  await expect(page.getByRole('heading', { name: 'Upload an APK' })).toBeVisible();
  await settle(page);
  await page.screenshot({ path: path.join(OUTPUT, 'upload-light.png'), fullPage: true });
});
