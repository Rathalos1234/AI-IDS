import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './',                       // this folder
  timeout: 60_000,
  retries: 0,
  fullyParallel: false,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    // Your UI is a hash router → we’ll navigate with '/#/<route>'
    baseURL: 'http://localhost:5173',
    headless: true,
    trace: 'on-first-retry',
    // Use the logged-in storage state produced by global setup:
    storageState: 'tests/ui/.auth/admin.json',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  // Optionally start the dev server for you; comment out if you prefer `make dev`
  // webServer: [
  //   { command: 'make dev', url: 'http://localhost:5173', reuseExistingServer: true, timeout: 120000 }
  // ],
  globalSetup: './global-setup.ts',
});
