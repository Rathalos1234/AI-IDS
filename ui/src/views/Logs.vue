<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { api } from '../api'

const items = ref([]); const err = ref(null); const loading = ref(false);
// PD-27 filters
const fIp = ref(''); const fSeverity = ref(''); const fType = ref(''); // alert|block
const fFrom = ref(''); const fTo = ref('');
let es



function normalize(e) {
  // unify table shape
  if (e.type === 'alert' || e.kind === 'ANOMALY' || e.kind === 'SIGNATURE') {
    return { id: e.id, ts: e.ts, ip: e.src_ip || e.ip, type: 'alert', detail: e.label || e.kind }
  }
  if (e.type === 'block' || e.action === 'block' || e.action === 'unblock') {
    return { id: e.id, ts: e.ts, ip: e.ip, type: e.action === 'block' ? 'block' : 'unblock', detail: e.action }
  }
  return { id: e.id, ts: e.ts, ip: e.ip || e.src_ip, type: e.type || e.kind || 'event', detail: e.label || '' }
}

async function initialLoad() {
  try {
    err.value = null
    const res = await api.logs?.({
      limit: 200,
      ip: fIp.value || undefined,
      severity: fSeverity.value || undefined,
      type: fType.value || undefined,
      from: fFrom.value || undefined,
      to: fTo.value || undefined,
    }) || { items: [] }
    const page = Array.isArray(res) ? res : (res.items || [])
    items.value = page.map(normalize)
  } catch (e) {
    err.value = e?.error || e?.message || 'Failed to load logs'
  }
}

function exportCsv(){
  api.exportLogs?.({
    ip: fIp.value || undefined,
    severity: fSeverity.value || undefined,
    type: fType.value || undefined,
    from: fFrom.value || undefined,
    to: fTo.value || undefined,
  }, 'csv');
}
function exportJson(){
  api.exportLogs?.({
    ip: fIp.value || undefined,
    severity: fSeverity.value || undefined,
    type: fType.value || undefined,
    from: fFrom.value || undefined,
    to: fTo.value || undefined,
  }, 'json');
}

function startSSE() {
  const base = localStorage.getItem('API_BASE') || ''
  es = new EventSource(base + '/api/events', { withCredentials: true })
  es.addEventListener('alert', (ev) => {
    const d = JSON.parse(ev.data); items.value.unshift(normalize({ ...d, type: 'alert' }))
  })
  es.addEventListener('block', (ev) => {
    const d = JSON.parse(ev.data); items.value.unshift(normalize({ ...d, type: 'block' }))
  })
  es.onerror = () => { /* network hiccup: keep connection open; browser will retry */ }
}

onMounted(async () => { await initialLoad(); startSSE() })
onBeforeUnmount(() => { if (es) es.close() })
</script>

<template>
  <div>
    <h1 style="margin:0 0 16px;">Log History</h1>
    <!-- PD-27: Filters + Export -->
    <div style="display:flex; flex-wrap:wrap; gap:8px; margin:8px 0;">
      <input class="input" v-model="fIp" placeholder="IP (e.g., 192.168.1.10)"/>
      <select class="input" v-model="fSeverity">
        <option value="">Severity (any)</option>
        <option>low</option><option>medium</option><option>high</option><option>critical</option>
      </select>
      <select class="input" v-model="fType">
        <option value="">Type (any)</option>
        <option value="alert">alert</option>
        <option value="block">block</option>
      </select>
      <input class="input" v-model="fFrom" placeholder="From (ISO) 2025-10-01T00:00:00Z" style="min-width:260px;"/>
      <input class="input" v-model="fTo" placeholder="To (ISO) 2025-10-31T23:59:59Z" style="min-width:260px;"/>
      <button class="btn" @click="initialLoad">Apply</button>
      <button class="btn" @click="exportCsv">Export CSV</button>
      <button class="btn" @click="exportJson">Export JSON</button>
    </div>
    <div v-if="err" style="color:#ff8080;margin-bottom:12px;">{{ err }}</div>

    <div style="background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <thead>
          <tr style="background:#0f141b;">
            <th style="text-align:left;padding:12px;">Date</th>
            <th style="text-align:left;padding:12px;">Time</th>
            <th style="text-align:left;padding:12px;">IP Address</th>
            <th style="text-align:left;padding:12px;">Type</th>
            <th style="text-align:left;padding:12px;">Details</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in items" :key="e.id + e.type" style="border-top:1px solid var(--border);">
            <td style="padding:12px;">{{ (e.ts||'').split('T')[0] }}</td>
            <td style="padding:12px;">{{ (e.ts||'').split('T')[1]?.slice(0,5) }}</td>
            <td style="padding:12px;">{{ e.ip }}</td>
            <td style="padding:12px; text-transform:capitalize;">{{ e.type }}</td>
            <td style="padding:12px;">{{ e.detail }}</td>
          </tr>
          <tr v-if="!items.length"><td colspan="5" style="padding:12px;color:var(--muted);">No events yet.</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
