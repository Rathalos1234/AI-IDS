<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue';
import { api } from '../api';
import { subscribeToEvents } from '../eventStream';
const items = ref([]);
const err = ref(null);
const loading = ref(false);

const fIp = ref('');
const fSeverity = ref('');
const fType = ref('');
const fFrom = ref('');
const fTo = ref('');

const unsubscribers = [];

function splitLabel(value) {
  const label = value || '';
  const match = String(label).match(/^(.*)\s+score=([-+]?\d*\.?\d+(?:e[-+]?\d+)?)/i);
  if (match) {
    return {
      text: match[1].trim(),
      score: Number(match[2]),
    };
  }
  return { text: label, score: null };
}

const formatScore = (score) => (typeof score === 'number' && score === score ? score.toFixed(3) : '—');

function normalize(event) {
  if (!event) return null;
  const ts = event.ts || event.timestamp || '';
  if (event.type === 'alert' || event.kind === 'ANOMALY' || event.kind === 'SIGNATURE') {
    const { text, score } = splitLabel(event.label || event.kind || '');
    return {
      id: event.id,
      ts,
      ip: event.src_ip || event.ip || '',
      type: 'alert',
      detail: text || (event.kind || ''),
      severity: event.severity || '',
      score,
    };
  }
  if (event.type === 'block' || event.action === 'block' || event.action === 'unblock') {
    const type = event.action === 'block' ? 'block' : 'unblock';
    return {
      id: event.id,
      ts,
      ip: event.ip || event.src_ip || '',
      type,
      detail: event.action || '',
      severity: event.severity || '',
      score: null,
    };
  }
  const { text, score } = splitLabel(event.label || event.detail || '');
  return {
    id: event.id,
    ts,
    ip: event.ip || event.src_ip || '',
    type: event.type || event.kind || 'event',
    detail: text,
    severity: event.severity || '',
    score,
  };
}

function passesFilters(row) {
  if (!row) return false;
  const ipFilter = fIp.value.trim();
  if (ipFilter && row.ip !== ipFilter) return false;
  const severityFilter = fSeverity.value.trim().toLowerCase();
  if (severityFilter && (row.severity || '').toLowerCase() !== severityFilter) return false;
  const typeFilter = fType.value.trim();
  if (typeFilter && row.type !== typeFilter) return false;
  const fromFilter = fFrom.value.trim();
  if (fromFilter && row.ts && row.ts < fromFilter) return false;
  const toFilter = fTo.value.trim();
  if (toFilter && row.ts && row.ts > toFilter) return false;
  return true;
}

async function initialLoad() {
  try {
    err.value = null;
    loading.value = true;
    const res = await (api.logs
      ? api.logs({
          limit: 200,
          ip: fIp.value || undefined,
          severity: fSeverity.value || undefined,
          type: fType.value || undefined,
          from: fFrom.value || undefined,
          to: fTo.value || undefined,
        })
      : { items: [] });
    const page = Array.isArray(res) ? res : res.items || [];
    const normalized = page.map(normalize).filter((row) => row && passesFilters(row));
    items.value = normalized;
  } catch (e) {
    err.value = e?.error || e?.message || 'Failed to load alerts';
  } finally {
    loading.value = false;
  }
}

function upsertRealtime(row) {
  if (!row) return;
  const idx = items.value.findIndex((entry) => entry.id === row.id && entry.type === row.type);
  if (!passesFilters(row)) {
    if (idx !== -1) items.value.splice(idx, 1);
    return;
  }
  if (idx !== -1) items.value.splice(idx, 1);
  items.value.unshift(row);
  if (items.value.length > 200) items.value.pop();
}

function subscribeStreams() {
  unsubscribers.push(
    subscribeToEvents('alert', (payload) => {
      const normalized = normalize({ ...payload, type: 'alert' });
      upsertRealtime(normalized);
    }),
  );
  unsubscribers.push(
    subscribeToEvents('block', (payload) => {
      const normalized = normalize(payload);
      upsertRealtime(normalized);
    }),
  );
}

async function exportCsv() {
  try {
    await api.exportLogs?.({
      ip: fIp.value || undefined,
      severity: fSeverity.value || undefined,
      type: fType.value || undefined,
      from: fFrom.value || undefined,
      to: fTo.value || undefined,
    }, 'csv');
  } catch (e) {
    err.value = e?.error || e?.message || 'Export failed';
  }
}

async function exportJson() {
  try {
    await api.exportLogs?.({
      ip: fIp.value || undefined,
      severity: fSeverity.value || undefined,
      type: fType.value || undefined,
      from: fFrom.value || undefined,
      to: fTo.value || undefined,
    }, 'json');
  } catch (e) {
    err.value = e?.error || e?.message || 'Export failed';
  }
}

onMounted(async () => {
  await initialLoad();
  subscribeStreams();
});

onBeforeUnmount(() => {
  while (unsubscribers.length) {
    const off = unsubscribers.pop();
    try { if (typeof off === 'function') off(); } catch (e) { console.error(e); }
  }
});

</script>

<template>
  <div class="fade-in">
    <div class="view-header">
      <div>
        <h1>Alerts</h1>
        <p>Filterable timeline of alerts and ban-list activity.</p>
      </div>
      <div class="actions-row">
        <button class="btn" @click="exportCsv">Export CSV</button>
        <button class="btn" @click="exportJson">Export JSON</button>
      </div>
    </div>
    <section class="surface surface--soft" style="margin-bottom:16px;">
      <div class="actions-row" style="flex-wrap:wrap; gap:12px;">
        <input class="input" v-model="fIp" placeholder="IP (e.g., 192.168.1.10)" style="min-width:180px;" />
        <select class="input" v-model="fSeverity">
          <option value="">Severity (any)</option>
          <option>low</option>
          <option>medium</option>
          <option>high</option>
          <option>critical</option>
        </select>
        <select class="input" v-model="fType">
          <option value="">Type (any)</option>
          <option value="alert">alert</option>
          <option value="block">block</option>
          <option value="unblock">unblock</option>
        </select>
        <input class="input" v-model="fFrom" placeholder="From ISO (2025-10-01T00:00:00Z)" style="min-width:220px;" />
        <input class="input" v-model="fTo" placeholder="To ISO" style="min-width:220px;" />
        <button class="btn btn--primary" @click="initialLoad" :disabled="loading">{{ loading ? 'Loading…' : 'Apply' }}</button>
      </div>
    </section>
    <div v-if="err" class="alert-banner" style="margin-bottom:16px;">{{ err }}</div>
    <section class="surface table-card">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>Time</th>
            <th>IP Address</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Details</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in items" :key="e.id + e.type">
            <td>{{ (e.ts||'').split('T')[0] }}</td>
            <td>{{ (e.ts||'').split('T')[1]?.slice(0,5) }}</td>
            <td>{{ e.ip }}</td>
            <td style="text-transform:capitalize;">{{ e.type }}</td>
            <td>{{ e.severity || '—' }}</td>
            <td>{{ e.detail }}</td>
            <td>{{ formatScore(e.score) }}</td>
          </tr>
          <tr v-if="!items.length">
            <td colspan="7" class="small" style="text-align:center;color:var(--muted);padding:18px;">No events yet.</td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
