// Normalize JSON responses; throw on HTTP errors
const TOKEN_KEY = 'ids.auth.token';
const TOKEN_EXP_KEY = 'ids.auth.expiry';

function clearStoredToken() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_EXP_KEY);
}

function getStoredToken() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return null;
  const expiryRaw = localStorage.getItem(TOKEN_EXP_KEY);
  if (expiryRaw) {
    const expiry = Number(expiryRaw);
    if (!Number.isFinite(expiry) || expiry <= Date.now()) {
      clearStoredToken();
      return null;
    }
  }
  return token;
}

function storeToken(token, expiresAt, ttlSeconds) {
  if (!token) {
    clearStoredToken();
    return;
  }
  localStorage.setItem(TOKEN_KEY, token);
  let expiry = null;
  if (expiresAt) {
    const parsed = Date.parse(expiresAt);
    if (!Number.isNaN(parsed)) expiry = parsed;
  }
  if (!expiry && ttlSeconds) {
    expiry = Date.now() + Number(ttlSeconds) * 1000;
  }
  if (expiry) {
    localStorage.setItem(TOKEN_EXP_KEY, String(expiry));
  } else {
    localStorage.removeItem(TOKEN_EXP_KEY);
  }
}

const parseJson = async (res) => {
  let body = null;
  try {
    body = await res.json();
  } catch (err) {
    body = null;
  }
  if (res.status === 401) {
    clearStoredToken();
  }
  if (!res.ok) {
    const error = new Error(body?.error || `HTTP ${res.status}`);
    if (body && typeof body === 'object') Object.assign(error, body);
    error.status = res.status;
    throw error;
  }
  return body ?? {};
};

const prefix = (path) => (window.API_BASE || localStorage.getItem('API_BASE') || '') + path;

const authFetch = (path, options = {}) => {
  const token = getStoredToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const finalOptions = {
    credentials: 'include',
    ...options,
    headers,
  };
  return fetch(prefix(path), finalOptions);
};

const authJson = (path, options = {}) => authFetch(path, options).then(parseJson);

export const trustedList = () => authJson('/api/trusted');



export const trustIp = (ip, note = '') =>
  authJson('/api/trusted', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, note }),
    });
    
export const untrustIp = (ip) =>
  authJson(`/api/trusted/${encodeURIComponent(ip)}`, {
    method: 'DELETE',
  });

export const blockIpWithDuration = (ip, { reason = '', duration_minutes = null } = {}) => {
  const payload = { ip, reason };
  if (duration_minutes != null) payload.duration_minutes = duration_minutes;
  return authJson('/api/blocks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
};


// ------- Existing functions (kept) -------
export const fetchAlerts = (limit = 100) =>
  authJson(`/api/alerts?limit=${encodeURIComponent(limit)}`);

export const fetchBlocks = (limit = 100) =>
  authJson(`/api/blocks?limit=${encodeURIComponent(limit)}`);

export const blockIp = (ip) =>
  authJson('/api/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });

export const unblockIp = (ip) =>
  authJson('/api/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });

// ------- Additions (non-breaking) -------

export const login = async (username, password) => {
  const res = await fetch(prefix('/api/auth/login'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    }).then(parseJson);
  if (res?.token) {
    storeToken(res.token, res.expires_at, res.ttl_seconds);
  }
  return res;
};

export const register = async (username, password) => {
  const res = await fetch(prefix('/api/auth/register'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }).then(parseJson);
  if (res?.token) {
    storeToken(res.token, res.expires_at, res.ttl_seconds);
  }
  return res;
};

export const resetPassword = async (username, password) =>
  fetch(prefix('/api/auth/reset-password'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  }).then(parseJson);


export const logout = async () => {
  try {
    await authJson('/api/auth/logout', { method: 'POST' });
  } finally {
    clearStoredToken();
  }
  return { ok: true };
};

// Stats
export const fetchStats = () => authJson('/api/stats');

// Alerts w/ pagination
export const fetchAlertsPaged = (limit = 50, cursor = null) => {
  const q = new URLSearchParams({ limit: String(limit) });
  if (cursor) q.set('cursor', cursor);
  return authJson(`/api/alerts?${q.toString()}`);
};

// Devices
export const fetchDevices = () => authJson('/api/devices');

// Settings
export const getSettings = () => authJson('/api/settings');

export const putSettings = (updates) =>
  authJson('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });

// Block with reason (keeps your original blockIp(ip) unchanged)
export const blockIpWithReason = (ip, reason) =>
  authJson('/api/blocks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, reason }),
  });

export const fetchLogs = (limit = 200) =>
  authJson(`/api/logs?limit=${encodeURIComponent(limit)}`);


export const startScan = (payload = {}) =>
  authJson('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

export const scanStatus = () => authJson('/api/scan/status');

// ---- PD-27 canonical helpers ----
// filters: { ip, severity, type, from, to, limit }
export const getLogs = (filters = {}) => {
  const q = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v != null && v !== '') q.set(k, String(v));
  });
  return authJson(`/api/logs?${q.toString()}`);
};
// Trigger a download directly (no blob handling needed in the caller)
export const exportLogs = async (filters = {}, format = 'csv') => {
  const q = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v != null && v !== '') q.set(k, String(v));
  });
  q.set('format', format);
  const res = await authFetch(`/api/logs/export?${q.toString()}`);
  if (res.status === 401) clearStoredToken();
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    const err = new Error(data?.error || `HTTP ${res.status}`);
    throw Object.assign(err, data);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ids_logs.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// --- PD-29: Ops helpers ---
export const health = () => authJson('/api/healthz');

export const runRetention = () => authJson('/api/retention/run', { method: 'POST' });

export const downloadDbBackup = async () => {
  const res = await authFetch('/api/backup/db');
  if (res.status === 401) clearStoredToken();
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.blob(); // caller can save-as
};

export const resetAllData = () => authJson('/api/ops/reset', { method: 'POST' });

export const api = {
  // Alerts (prefers paged if present)
  alerts: (limit = 50, cursor = null) =>
    (typeof fetchAlertsPaged === 'function' ? fetchAlertsPaged : fetchAlerts)(limit, cursor),
  blocks: fetchBlocks,
  block: (ip, reason) =>
    reason && typeof blockIpWithReason === 'function' ? blockIpWithReason(ip, reason) : blockIp(ip),
  unblock: unblockIp,

  // Trusted IP management
  trustedList: typeof trustedList === 'function' ? trustedList : undefined,
  trustIp: typeof trustIp === 'function' ? trustIp : undefined,
  untrustIp: typeof untrustIp === 'function' ? untrustIp : undefined,
  blockIpWithDuration: typeof blockIpWithDuration === 'function' ? blockIpWithDuration : undefined,

  // Logs
  logs: typeof getLogs === 'function' ? getLogs : (filters) => fetchLogs(filters?.limit || 200),
  exportLogs: typeof exportLogs === 'function' ? exportLogs : undefined,

  // Stats / Devices / Settings (only used if you added them earlier)
  stats: typeof fetchStats === 'function' ? fetchStats : undefined,
  devices: typeof fetchDevices === 'function' ? fetchDevices : undefined,
  getSettings: typeof getSettings === 'function' ? getSettings : undefined,
  putSettings: typeof putSettings === 'function' ? putSettings : undefined,

  // Network scanning helpers
  startScan: typeof startScan === 'function' ? startScan : undefined,
  scanStatus: typeof scanStatus === 'function' ? scanStatus : undefined,

  // Auth (optional)
  login: typeof login === 'function' ? login : undefined,
  register: typeof register === 'function' ? register : undefined,
  resetPassword: typeof resetPassword === 'function' ? resetPassword : undefined,
  logout: typeof logout === 'function' ? logout : undefined,

  // Ops helpers
  health: typeof health === 'function' ? health : undefined,
  runRetention: typeof runRetention === 'function' ? runRetention : undefined,
  downloadDbBackup: typeof downloadDbBackup === 'function' ? downloadDbBackup : undefined,
  resetAllData: typeof resetAllData === 'function' ? resetAllData : undefined,
};

export const authToken = {
  get: getStoredToken,
  clear: clearStoredToken,
};
