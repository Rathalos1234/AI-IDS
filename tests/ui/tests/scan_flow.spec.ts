import { test, expect } from '@playwright/test';

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || 'sprint_artifacts/ui';

async function login(page, email='test@example.com', password='test123!') {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).toHaveURL(/dashboard/i);
}

test('IT-15 Scan flow: start → progress → devices refresh', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  await page.getByRole('button', { name: /scan network/i }).click();
  await expect(page.getByTestId('scan-progress')).toBeVisible();
  await expect(page.getByTestId('scan-progress')).toContainText('100%');
  await page.goto('/devices');
  await expect(page.getByTestId('last-scan')).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/IT-15_scan_flow.png` });
});
