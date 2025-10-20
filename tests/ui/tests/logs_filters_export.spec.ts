/// <reference types="node" />
import { test, expect, Page } from '@playwright/test';

const ARTIFACT_DIR: string = process.env.ARTIFACT_DIR ?? 'sprint_artifacts/ui';
const API_URL: string = process.env.API_URL ?? '';

async function login(page: Page, user: string = 'admin', pass: string = 'admin') {
  await page.goto('/dashboard').catch(() => {});
  if (await page.getByTestId('last-update').first().isVisible({ timeout: 1000 }).catch(()=>false)) return;
  await page.goto('/login').catch(() => {});
  const emailSel = page.getByLabel(/email/i).or(page.getByPlaceholder(/email/i)).or(page.locator('input[type="email"], input[name="email"]'));
  const pwSel = page.getByLabel(/password/i).or(page.getByPlaceholder(/password/i)).or(page.locator('input[type="password"], input[name="password"]'));
  const hasForm = await emailSel.first().isVisible({ timeout: 1500 }).catch(()=>false);
  if (hasForm) {
    await emailSel.fill(user);
    await pwSel.fill(pass);
    await page.getByRole('button', { name: /sign in|log in|login/i }).click();
    await expect(page).toHaveURL(/dashboard|alerts|devices/i);
    return;
  }
  const loginEndpoint = API_URL ? `${API_URL}/api/login` : '/api/login';
  const ok = await page.evaluate(async (url: string) => {
    const res = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify({username:'admin', password:'admin'})});
    return res.status === 200 || res.status === 204;
  }, loginEndpoint);
  if (!ok) throw new Error('API login failed (fallback).');
  await page.goto('/dashboard');
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
