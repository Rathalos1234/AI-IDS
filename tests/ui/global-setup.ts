import { request, FullConfig } from '@playwright/test';

export default async function globalSetup(_config: FullConfig) {
  // Log into API and stash cookie to storageState
  const api = await request.newContext({
    baseURL: process.env.API_URL || 'http://127.0.0.1:5000',
  });

  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin';

  // Adjust creds if you changed them in ENV:
  const res = await api.post('/api/auth/login', {
    data: { username, password },
  });
  if (!res.ok()) throw new Error(`Login failed: ${res.status()} ${await res.text()}`);

  // Create a browser storage state that includes auth cookie from API origin
  await api.storageState({ path: 'tests/ui/.auth/admin.json' });
  await api.dispose();
}
