import { test, expect } from '@playwright/test';

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || 'sprint_artifacts/ui';

async function login(page, email='test@example.com', password='test123!') {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await expect(page).toHaveURL(/dashboard/i);
}

test('IT-16 Logs filters & export', async ({ page }) => {
  await login(page);
  await page.goto('/logs');
  await page.getByRole('combobox', { name: /severity/i }).selectOption('high');
  await page.getByRole('combobox', { name: /type/i }).selectOption('signature');
  await page.getByLabel(/from/i).fill('2025-01-01');
  await page.getByLabel(/to/i).fill('2025-12-31');
  await expect(page.locator('[data-test=history-row]').first()).toBeVisible({ timeout: 2000 });
  await page.getByRole('button', { name: /export csv/i }).click();
  await page.getByRole('button', { name: /export json/i }).click();
  await page.screenshot({ path: `${ARTIFACT_DIR}/IT-16_logs_filters_export.png` });
});
