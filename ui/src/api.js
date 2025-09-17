const j = (res) => {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
};

export const fetchAlerts = (limit = 100) =>
  fetch(`/api/alerts?limit=${encodeURIComponent(limit)}`).then(j);

export const fetchBlocks = (limit = 100) =>
  fetch(`/api/blocks?limit=${encodeURIComponent(limit)}`).then(j);

export const blockIp = (ip) =>
  fetch(`/api/block`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  }).then(j);

export const unblockIp = (ip) =>
  fetch(`/api/unblock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  }).then(j);
