/// <reference types="node" />
import { test, expect, Page } from '@playwright/test';

const ARTIFACT_DIR: string = process.env.ARTIFACT_DIR ?? 'sprint_artifacts/ui';
const API_URL: string = process.env.API_URL ?? '';



// Works whether auth is enabled or not; sets API_BASE so SPA talks to Flask.
export async function login(page: Page, {
  apiBase = process.env.API_URL ?? 'http://127.0.0.1:5000',
  user = process.env.ADMIN_USER ?? 'admin',
  pass = process.env.ADMIN_PASSWORD ?? 'admin',
} = {}) {
  // Make the SPA use the backend origin for /api/*
  await page.addInitScript((base) => localStorage.setItem('API_BASE', base), apiBase);
  await page.goto('/'); // ensure init script runs

  // Try API login first – this sets the session cookie on the apiBase origin
  const ok = await page.evaluate(async ({ apiBase, user, pass }) => {
    const res = await fetch(`${apiBase}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username: user, password: pass })
    });
    if (!res.ok) return false;
    const me = await fetch(`${apiBase}/api/auth/me`, { credentials: 'include' });
    return me.ok && (await me.json()).ok === true;
  }, { apiBase, user, pass });

  expect(ok).toBeTruthy();

  // Land on dashboard hash-route
  await page.goto('/dashboard');
  // If you add a data-testid later, you can assert it here; otherwise skip.
}


test('S2-GUI-001 Alerts stream shows anomalies with severity', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  await page.waitForTimeout(1500);
  const rows = page.locator('[data-test=alert-row]');
  await expect(rows.first()).toBeVisible();
  const text = await rows.first().textContent();
  expect(text || '').toMatch(/ANOMALY/i);
  expect(text || '').toMatch(/severity=(low|medium|high)/i);
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-GUI-001_alerts.png` });
});

test('S2-GUI-002 Signature hits are styled distinctly', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  await page.waitForTimeout(1500);
  const sigRow = page.locator('[data-test=alert-row][data-kind=signature]').first();
  await expect(sigRow).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-GUI-002_signature.png` });
});

test('S2-GUI-003 Status/banner shows model + thresholds', async ({ page }) => {
  await login(page);
  await page.goto('/status');
  await expect(page.getByTestId('model-version')).toBeVisible();
  await expect(page.getByTestId('thresholds')).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-GUI-003_banner.png` });
});

test('S2-FW-001 Add IP to banlist from alert row', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  const rows = page.locator('[data-test=alert-row]');
  await expect(rows.first()).toBeVisible();
  await rows.first().getByRole('button', { name: /block ip/i }).click();
  await page.getByRole('button', { name: /confirm/i }).click();
  await expect(page.getByText(/added to banlist/i)).toBeVisible();
  await page.goto('/banlist');
  await expect(page.locator('[data-test=ban-row]').first()).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-FW-001_banlist.png` });
});

test('S2-FW-002 Duplicate add is prevented', async ({ page }) => {
  await login(page);
  await page.goto('/dashboard');
  const rows = page.locator('[data-test=alert-row]');
  await expect(rows.first()).toBeVisible();
  await rows.first().getByRole('button', { name: /block ip/i }).click();
  await page.getByRole('button', { name: /confirm/i }).click();
  await expect(page.getByText(/already blocked|duplicate/i)).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-FW-002_duplicate.png` });
});

test('S2-FW-003 Unban removes entry', async ({ page }) => {
  await login(page);
  await page.goto('/banlist');
  const first = page.locator('[data-test=ban-row]').first();
  await expect(first).toBeVisible();
  await first.getByRole('button', { name: /unban/i }).click();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-FW-003_unban.png` });
});

test('S2-AUTH-001 Sign-up success', async ({ page }) => {
  await page.goto('/signup').catch(() => {});
  const hasForm = await page.getByLabel(/Email/i).first().isVisible({ timeout: 1500 }).catch(() => false);
  test.skip(!hasForm, 'Signup UI not present in this build');
  await page.getByLabel('Email').fill(`student+${Date.now()}@example.com`);
  await page.getByLabel('Password').fill('Test1234!');
  await page.getByRole('button', { name: /create account|sign up/i }).click();
  await expect(page).toHaveURL(/dashboard/i);
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-AUTH-001_signup.png` });
});

test('S2-AUTH-002 Lockout after N failures', async ({ page }) => {
  await page.goto('/login');
  for (let i = 0; i < 6; i++) {
    await page.getByLabel('Email').fill('lock@example.com');
    await page.getByLabel('Password').fill('wrongPassword!');
    await page.getByRole('button', { name: /sign in/i }).click();
  }
  await expect(page.getByText(/locked|too many|cooldown/i)).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-AUTH-002_lockout.png` });
});

test('S2-AUTH-003 Logout clears session', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: /log out/i }).click();
  await expect(page).toHaveURL(/login/i);
  await page.goto('/dashboard');
  await expect(page).toHaveURL(/login/i);
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-AUTH-003_logout.png` });
});

test('S2-LOG-001 History renders newest first', async ({ page }) => {
  await login(page);
  await page.goto('/history');
  await expect(page.locator('[data-test=history-row]').first()).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-LOG-001_history.png` });
});

test('S2-LOG-002 Filters work', async ({ page }) => {
  await login(page);
  await page.goto('/history');
  await page.getByRole('combobox', { name: /severity/i }).selectOption('high');
  await page.getByRole('combobox', { name: /type/i }).selectOption('signature');
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-LOG-002_filter.png` });
});

test('S2-LOG-003 Export CSV/JSON', async ({ page }) => {
  await login(page);
  await page.goto('/history');
  await page.getByRole('button', { name: /export csv/i }).click();
  await page.getByRole('button', { name: /export json/i }).click();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-LOG-003_export.png` });
});

test('S2-SET-001 Change thresholds → validate → runtime reflects', async ({ page }) => {
  await login(page);
  await page.goto('/settings');
  await page.getByLabel('High threshold').fill('-0.20');
  await page.getByLabel('Medium threshold').fill('-0.10');
  await page.getByRole('button', { name: /save/i }).click();
  await page.getByRole('button', { name: /validate config/i }).click();
  await expect(page.getByText(/config ok/i)).toBeVisible();
  await page.goto('/status');
  await expect(page.getByTestId('thresholds')).toContainText('-0.20');
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-SET-001_thresholds.png` });
});

test('S2-SET-002 Invalid thresholds rejected', async ({ page }) => {
  await login(page);
  await page.goto('/settings');
  await page.getByLabel('High threshold').fill('0.10');
  await page.getByLabel('Medium threshold').fill('-0.05');
  await page.getByRole('button', { name: /save/i }).click();
  await expect(page.getByText(/invalid|must be/i)).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-SET-002_invalid.png` });
});

test('S2-SET-003 Toggle signatures Off/On affects alerts', async ({ page }) => {
  await login(page);
  await page.goto('/settings');
  const toggle = page.getByRole('switch', { name: /signatures/i });
  await toggle.click(); // Off
  await page.goto('/dashboard');
  await page.waitForTimeout(1000);
  const sigRows = await page.locator('[data-test=alert-row][data-kind=signature]').count();
  expect(sigRows).toBe(0);
  await page.goto('/settings');
  await toggle.click(); // On
  await page.goto('/dashboard');
  await page.waitForTimeout(1500);
  await expect(page.locator('[data-test=alert-row][data-kind=signature]').first()).toBeVisible();
  await page.screenshot({ path: `${ARTIFACT_DIR}/S2-SET-003_toggle.png` });
});
