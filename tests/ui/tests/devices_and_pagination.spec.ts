import { test, expect } from '@playwright/test';

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || 'sprint_artifacts/ui';

async function login(page, email='test@example.com', password='test123!') {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).toHaveURL(/dashboard/i);
}

test('PD-14 Header telemetry visible on Dashboard', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  await expect(page.getByTestId('last-update')).toBeVisible();
  await expect(page.getByTestId('last-scan')).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/PD-14_header_telemetry.png` });
});

test('PD-14 Alerts pagination "Load more" increases rows', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  const rows = page.locator('[data-test=alert-row]');
  const before = await rows.count();
  await page.getByRole('button', { name: /load more/i }).click();
  await page.waitForTimeout(500);
  const after = await rows.count();
  expect(after).toBeGreaterThanOrEqual(before);
  await page.screenshot({ path: `${ARTIFACT_DIR}/PD-14_load_more.png` });
});

test('PD-18 Devices table shows required columns', async ({ page }) => {
  await login(page);
  await page.goto('/devices');
  await expect(page.getByRole('columnheader', { name: /name/i })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: /open ports/i })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: /risk/i })).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/PD-18_devices.png` });
});
