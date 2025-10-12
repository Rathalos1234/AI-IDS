// Normalize JSON responses; throw on HTTP errors
const j = (res) => {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

// Optional base URL + credentials (works for same-origin or cross-origin dev)
const prefix = (path) => (window.API_BASE || localStorage.getItem('API_BASE') || '') + path;
const CRED = { credentials: 'include' };



// ---- PD-28: Trusted IPs + temp bans ----
export const trustedList = () =>
  fetch(prefix('/api/trusted'), { ...CRED }).then(j);
export const trustIp = (ip, note = '') =>
  fetch(prefix('/api/trusted'), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, note }), ...CRED,
  }).then(j);
export const untrustIp = (ip) =>
  fetch(prefix(`/api/trusted/${encodeURIComponent(ip)}`), {
    method: 'DELETE', ...CRED,
  }).then(j);
export const blockIpWithDuration = (ip, { reason = '', duration_minutes = null } = {}) => {
  const payload = { ip, reason };
  if (duration_minutes != null) payload.duration_minutes = duration_minutes;
  return fetch(prefix('/api/blocks'), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload), ...CRED,
  }).then(j);
};


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
  fetch((window.API_BASE || localStorage.getItem('API_BASE') || '') + '/api/devices', {
    credentials: 'include'
  }).then(res => { if(!res.ok) throw new Error(`HTTP ${res.status}`); return res.json(); });

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


export const startScan = (payload = {}) =>
  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(payload),
  }).then(j);

export const scanStatus = () =>
  fetch('/api/scan/status', { credentials: 'include' }).then(j);

// ---- PD-27 canonical helpers ----
// filters: { ip, severity, type, from, to, limit }
export const getLogs = (filters = {}) => {
  const q = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v != null && v !== '') q.set(k, String(v));
  });
  return fetch(prefix(`/api/logs?${q.toString()}`), { ...CRED }).then(j);
};
// Trigger a download directly (no blob handling needed in the caller)
export const exportLogs = (filters = {}, format = 'csv') => {
  const q = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v != null && v !== '') q.set(k, String(v));
  });
  q.set('format', format);
  window.location.href = prefix(`/api/logs/export?${q.toString()}`);
};

// --- PD-29: Ops helpers ---
export const health = () =>
  fetch(prefix('/api/healthz'), { ...CRED }).then(j);

export const runRetention = () =>
  fetch(prefix('/api/retention/run'), { method: 'POST', ...CRED }).then(j);

export const downloadDbBackup = async () => {
  const res = await fetch(prefix('/api/backup/db'), { ...CRED });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.blob(); // caller can save-as
};

if (typeof api !== 'undefined') {
  api.health = health;
  api.runRetention = runRetention;
  api.downloadDbBackup = downloadDbBackup;
  api.logs = getLogs;
  api.exportLogs = exportLogs;
  api.trustedList = trustedList;
  api.trustIp = trustIp;
  api.untrustIp = untrustIp;
  api.blockIpWithDuration = blockIpWithDuration;  
}
