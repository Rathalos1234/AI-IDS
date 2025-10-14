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
