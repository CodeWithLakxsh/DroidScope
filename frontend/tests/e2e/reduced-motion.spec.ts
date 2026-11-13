/**
 * Verifies the application is fully usable with motion disabled.
 *
 * The risk with any animation system is that content which animates in stays
 * invisible when the animation is suppressed. These tests run the real UI with
 * `prefers-reduced-motion: reduce` and assert the content is present and
 * visible anyway.
 */

import { expect, test } from '@playwright/test';

test.use({ reducedMotion: 'reduce' });

test.describe('with reduced motion', () => {
  test('dashboard content is visible without animation', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

    const tile = page.locator('.ds-surface').first();
    await expect(tile).toBeVisible();

    // Entrance utilities use animation-fill-mode: both, which would strand an
    // element at opacity 0 if the reduced-motion rules did not reset it.
    const opacity = await tile.evaluate((el) => getComputedStyle(el).opacity);
    expect(Number(opacity)).toBe(1);
  });

  test('entrance animations are suppressed, not merely shortened', async ({ page }) => {
    await page.goto('/scans');
    const animated = page.locator('.ds-animate-rise').first();
    await expect(animated).toBeVisible();

    const state = await animated.evaluate((el) => {
      const style = getComputedStyle(el);
      return { name: style.animationName, opacity: style.opacity };
    });
    expect(state.name).toBe('none');
    expect(Number(state.opacity)).toBe(1);
  });

  test('table rows are visible without their stagger', async ({ page }) => {
    await page.goto('/findings');
    await page.waitForURL(/\/findings\/[0-9a-f]+/, { timeout: 30_000 });

    const row = page.locator('tbody tr').first();
    await expect(row).toBeVisible({ timeout: 30_000 });
    const opacity = await row.evaluate((el) => getComputedStyle(el).opacity);
    expect(Number(opacity)).toBe(1);
  });

  test('counters show their final value immediately', async ({ page }) => {
    await page.goto('/');
    // The accessible name is always the true value; with motion reduced the
    // rendered text must match it rather than tweening from zero.
    const counter = page.locator('[aria-label]').filter({ hasText: /^\d/ }).first();
    if (await counter.count()) {
      const label = await counter.getAttribute('aria-label');
      await expect(counter).toHaveText(Number(label).toLocaleString());
    }
  });

  test('the full workflow still works', async ({ page }) => {
    await page.goto('/scans');
    const link = page.locator('tbody tr a').first();
    await expect(link).toBeVisible({ timeout: 30_000 });
    await link.click();
    await expect(page.getByRole('heading', { name: 'Analyzer coverage' })).toBeVisible();
  });
});
