// Normalize JSON responses; throw on HTTP errors
const j = (res) => {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

// Optional base URL + credentials (works for same-origin or cross-origin dev)
const prefix = (path) => (window.API_BASE || localStorage.getItem('API_BASE') || '') + path;
const CRED = { credentials: 'include' };

// ------- Existing functions (kept) -------
export const fetchAlerts = (limit = 100) =>
  fetch(prefix(`/api/alerts?limit=${encodeURIComponent(limit)}`), { ...CRED }).then(j);

export const fetchBlocks = (limit = 100) =>
  fetch(prefix(`/api/blocks?limit=${encodeURIComponent(limit)}`), { ...CRED }).then(j);

export const blockIp = (ip) =>
  fetch(prefix(`/api/block`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
    ...CRED,
  }).then(j);

export const unblockIp = (ip) =>
  fetch(prefix(`/api/unblock`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
    ...CRED,
  }).then(j);

// ------- Additions (non-breaking) -------

// Auth
export const login = (username, password) =>
  fetch(prefix('/api/auth/login'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    ...CRED,
  }).then(j);

export const logout = () =>
  fetch(prefix('/api/auth/logout'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    ...CRED,
  }).then(j);

// Stats
export const fetchStats = () =>
  fetch(prefix('/api/stats'), { ...CRED }).then(j);

// Alerts w/ pagination
export const fetchAlertsPaged = (limit = 50, cursor = null) => {
  const q = new URLSearchParams({ limit: String(limit) });
  if (cursor) q.set('cursor', cursor);
  return fetch(prefix(`/api/alerts?${q.toString()}`), { ...CRED }).then(j);
};

// Devices
export const fetchDevices = () =>
  fetch(prefix('/api/devices'), { ...CRED }).then(j);

// Settings
export const getSettings = () =>
  fetch(prefix('/api/settings'), { ...CRED }).then(j);

export const putSettings = (updates) =>
  fetch(prefix('/api/settings'), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
    ...CRED,
  }).then(j);

// Block with reason (keeps your original blockIp(ip) unchanged)
export const blockIpWithReason = (ip, reason) =>
  fetch(prefix('/api/blocks'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
    ...CRED,
  }).then(j);

  // --- add this at the very end of ui/src/api.js ---

export const api = {
  // Alerts (prefers paged if present)
  alerts: (limit = 50, cursor = null) =>
    typeof fetchAlertsPaged === 'function'
      ? fetchAlertsPaged(limit, cursor)
      : fetchAlerts(limit),

  // Blocks
  blocks: fetchBlocks,
  block: (ip, reason) =>
    reason && typeof blockIpWithReason === 'function'
      ? blockIpWithReason(ip, reason)
      : blockIp(ip),
  unblock: unblockIp,

  // Stats / Devices / Settings (only used if you added them earlier)
  stats: typeof fetchStats === 'function' ? fetchStats : undefined,
  devices: typeof fetchDevices === 'function' ? fetchDevices : undefined,
  getSettings: typeof getSettings === 'function' ? getSettings : undefined,
  putSettings: typeof putSettings === 'function' ? putSettings : undefined,

  // Auth (optional)
  login: typeof login === 'function' ? login : undefined,
  logout: typeof logout === 'function' ? logout : undefined,
};


export const fetchLogs = (limit = 200) =>
  fetch(prefix(`/api/logs?limit=${encodeURIComponent(limit)}`), { ...CRED }).then(j);
